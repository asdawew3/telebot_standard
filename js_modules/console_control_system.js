/**
 * 控制台接管系统
 * 用于接管浏览器的控制台，实现命令执行和日志捕获
 * 
 * 提供以下功能：
 * 1. 接管浏览器控制台的所有日志输出
 * 2. 提供执行JavaScript命令的接口
 * 3. 保存日志历史记录
 * 4. 提供获取日志的接口
 */

// 控制台日志缓冲区
let consoleBuffer = [];

// 最大缓冲区大小
const MAX_BUFFER_SIZE = 1000;

// 日志类型
const LOG_TYPES = {
    LOG: 'log',
    INFO: 'info',
    WARN: 'warning',
    ERROR: 'error',
    DEBUG: 'debug'
};

// 原始控制台方法
const originalConsole = {
    log: console.log,
    info: console.info,
    warn: console.warn,
    error: console.error,
    debug: console.debug,
    clear: console.clear
};

/**
 * 添加日志到缓冲区
 * 
 * @param {string} type - 日志类型
 * @param {Array} args - 日志参数
 */
function addToBuffer(type, args) {
    try {
        // 转换参数为字符串
        let content = '';
        
        try {
            // 处理复杂对象
            content = Array.from(args).map(arg => {
                if (arg === null) {
                    return 'null';
                } else if (arg === undefined) {
                    return 'undefined';
                } else if (typeof arg === 'object') {
                    try {
                        // 对于DOM元素，返回简化描述
                        if (arg instanceof HTMLElement) {
                            return `<${arg.tagName.toLowerCase()}${arg.id ? ' id="' + arg.id + '"' : ''}${arg.className ? ' class="' + arg.className + '"' : ''}>`;
                        }
                        
                        // 对于错误对象，返回错误信息
                        if (arg instanceof Error) {
                            return `${arg.name}: ${arg.message}\n${arg.stack || ''}`;
                        }
                        
                        // 对于其他对象，尝试JSON序列化
                        return JSON.stringify(arg, null, 2);
                    } catch (e) {
                        return String(arg);
                    }
                } else if (typeof arg === 'function') {
                    // 对于函数，返回函数定义
                    return `[Function: ${arg.name || 'anonymous'}]`;
                }
                return String(arg);
            }).join(' ');
        } catch (e) {
            // 如果上述处理失败，尝试直接转换为字符串
            try {
                content = String(args);
            } catch (e2) {
                content = '[无法序列化的内容]';
                originalConsole.error('[控制台系统] 无法序列化日志内容:', e2);
            }
        }
        
        // 创建日志对象
        const logEntry = {
            type: 'console',
            content: content,
            timestamp: Date.now(),
            level: type
        };
        
        // 添加到缓冲区
        consoleBuffer.push(logEntry);
        
        // 限制缓冲区大小
        if (consoleBuffer.length > MAX_BUFFER_SIZE) {
            consoleBuffer = consoleBuffer.slice(-MAX_BUFFER_SIZE);
        }
    } catch (e) {
        // 确保错误不会中断控制台
        originalConsole.error('[控制台系统] 添加日志到缓冲区时发生错误:', e);
    }
}

/**
 * 初始化控制台接管
 * 重写控制台方法，捕获所有日志
 */
function initConsoleControl() {
    try {
        // 重写控制台方法
        console.log = function() {
            // 调用原始方法
            originalConsole.log.apply(console, arguments);
            // 添加到缓冲区
            addToBuffer(LOG_TYPES.LOG, arguments);
        };
        
        console.info = function() {
            originalConsole.info.apply(console, arguments);
            addToBuffer(LOG_TYPES.INFO, arguments);
        };
        
        console.warn = function() {
            originalConsole.warn.apply(console, arguments);
            addToBuffer(LOG_TYPES.WARN, arguments);
        };
        
        console.error = function() {
            originalConsole.error.apply(console, arguments);
            addToBuffer(LOG_TYPES.ERROR, arguments);
        };
        
        console.debug = function() {
            originalConsole.debug.apply(console, arguments);
            addToBuffer(LOG_TYPES.DEBUG, arguments);
        };
        
        console.clear = function() {
            originalConsole.clear.apply(console, arguments);
            // 清空缓冲区
            consoleBuffer = [];
            // 添加清空日志
            addToBuffer(LOG_TYPES.INFO, ['控制台已清空']);
        };
        
        // 添加初始化成功日志
        console.info('控制台接管系统初始化成功');
        
        return {
            success: true,
            message: '控制台接管系统初始化成功',
            buffer_size: consoleBuffer.length
        };
    } catch (e) {
        originalConsole.error('[控制台系统] 控制台接管系统初始化失败:', e);
        return {
            success: false,
            message: '控制台接管系统初始化失败: ' + e.message,
            error: e.message
        };
    }
}

/**
 * 获取控制台日志
 * 
 * @param {number} limit - 获取的日志数量限制
 * @returns {Array} - 日志数组
 */
function getConsoleLogs(limit = 100) {
    try {
        // 获取最近的日志
        const logs = limit ? consoleBuffer.slice(-limit) : consoleBuffer;
        
        return {
            success: true,
            logs: logs
        };
    } catch (e) {
        originalConsole.error('[控制台系统] 获取控制台日志失败:', e);
        return {
            success: false,
            message: '获取控制台日志失败: ' + e.message,
            error: e.message
        };
    }
}

/**
 * 清空控制台日志
 * 
 * @returns {Object} - 清空结果
 */
function clearConsoleLogs() {
    try {
        // 清空缓冲区
        consoleBuffer = [];
        return {
            success: true,
            message: '控制台日志已清空'
        };
    } catch (e) {
        originalConsole.error('清空控制台日志失败:', e);
        return {
            success: false,
            message: '清空控制台日志失败: ' + e.message,
            error: e.message
        };
    }
}

/**
 * 执行JavaScript命令
 * 
 * @param {string} command - 要执行的命令
 * @returns {Object} - 执行结果
 */
function executeConsoleCommand(command) {
    try {
        // 记录命令
        console.info('> ' + command);
        
        // 执行命令
        const result = eval(command);
        
        // 确保结果显示在控制台中，特别处理对象类型
        if (result === undefined) {
            console.log('undefined');
        } else if (result === null) {
            console.log('null');
        } else if (typeof result === 'object') {
            // 对于对象，尝试格式化输出
            try {
                if (result instanceof HTMLElement) {
                    console.log(`<${result.tagName.toLowerCase()}${result.id ? ' id="' + result.id + '"' : ''}${result.className ? ' class="' + result.className + '"' : ''}>`);
                } else if (result instanceof Error) {
                    console.log(`${result.name}: ${result.message}\n${result.stack || ''}`);
                } else if (Array.isArray(result)) {
                    console.log(JSON.stringify(result, null, 2));
                } else {
                    // 对于普通对象，使用console.dir以便更好地展示结构
                    console.dir(result);
                    // 同时输出字符串形式，确保在缓冲区中有记录
                    console.log(JSON.stringify(result, null, 2));
                }
            } catch (e) {
                console.log(String(result));
                originalConsole.error('[控制台系统] 格式化结果对象失败:', e);
            }
        } else {
            // 对于基本类型，直接输出
            console.log(result);
        }
        
        return {
            success: true,
            result: result
        };
    } catch (e) {
        // 输出错误
        console.error('执行错误: ' + e.message);
        
        return {
            success: false,
            message: e.message,
            error: e.message
        };
    }
}

// 导出函数
window.initConsoleControl = initConsoleControl;
window.getConsoleLogs = getConsoleLogs;
window.clearConsoleLogs = clearConsoleLogs;
window.executeConsoleCommand = executeConsoleCommand;

// 自动初始化
initConsoleControl();

// 输出可调用方法的说明
console.info('控制台接管系统提供以下可调用方法：');
console.info('1. initConsoleControl() - 初始化控制台接管系统，无参数，自动执行');
console.info('2. getConsoleLogs(limit) - 获取控制台日志，参数：limit(数字，可选，默认100) - 获取的日志数量限制');
console.info('3. clearConsoleLogs() - 清空控制台日志，无参数');
console.info('4. executeConsoleCommand(command) - 执行JavaScript命令，参数：command(字符串) - 要执行的JavaScript命令');
console.info('所有方法均通过window对象全局暴露，可直接调用，例如：window.executeConsoleCommand("alert(\'测试\')")'); 