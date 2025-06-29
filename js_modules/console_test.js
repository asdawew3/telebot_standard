// ================================
// Telegram Web 自动化测试代码
// 在浏览器F12控制台中粘贴执行
// ================================

// 全局变量
let testConfig = {
    debug: true,
    maxWaitTime: 8000,  // 最大等待时间减少到 8秒
    buttonCheckInterval: 50,  // 按钮状态检查间隔优化到 50ms
    sendDelay: 50,  // 发送前延迟优化到 50ms
    messageCheckDelay: 50,  // 消息检查延迟优化到 50ms
    useMutationObserver: true,  // 优先使用MutationObserver
    paginationDelay: 75,  // 翻页检测延迟优化到 75ms
    contentCheckInterval: 50  // 内容检测间隔优化到 50ms
};

// 确保全局函数在注入后可用
window.testConfig = testConfig; 

// 日志工具
function log(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = `[${timestamp}]`;
    
    switch(type) {
        case 'error':
            console.error(`${prefix} 错误 ${message}`);
            break;
        case 'success':
            console.log(`${prefix} 成功 ${message}`);
            break;
        case 'warning':
            console.warn(`${prefix} 警告 ${message}`);
            break;
        case 'debug':
            if (testConfig.debug) {
                console.log(`${prefix} 调试 ${message}`);
            }
            break;
        default:
            console.log(`${prefix} 信息 ${message}`);
    }
}

// 确保日志函数在全局可用
window.log = log;

// 等待延迟
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// 获取输入框
function getInputBox() {
    const selectors = [
        '[contenteditable="true"][data-testid="message-input"]',
        '.editable-message-text[contenteditable="true"]',
        '[contenteditable="true"].ProseMirror',
        'div[contenteditable="true"]'
    ];
    
    for (const selector of selectors) {
        const element = document.querySelector(selector);
        if (element) {
            log(`找到输入框: ${selector}`, 'debug');
            return element;
        }
    }
    
    log('未找到输入框', 'error');
    return null;
}

// 清空输入框
function clearInputBox(inputBox) {
    try {
        inputBox.focus();
        document.execCommand('selectAll');
        document.execCommand('delete');
        inputBox.innerHTML = '';
        inputBox.textContent = '';
        
        inputBox.dispatchEvent(new KeyboardEvent('keydown', {
            key: 'a',
            ctrlKey: true,
            bubbles: true
        }));
        
        inputBox.dispatchEvent(new KeyboardEvent('keydown', {
            key: 'Delete',
            bubbles: true
        }));
        
        log('输入框已清空', 'debug');
        return true;
    } catch (error) {
        log(`清空输入框失败: ${error.message}`, 'error');
        return false;
    }
}

// 输入消息
function inputMessage(inputBox, message) {
    try {
        clearInputBox(inputBox);
        
        inputBox.focus();
        inputBox.textContent = message;
        inputBox.innerHTML = message;
        
        inputBox.dispatchEvent(new Event('input', { bubbles: true }));
        inputBox.dispatchEvent(new Event('change', { bubbles: true }));
        
        for (let char of message) {
            inputBox.dispatchEvent(new KeyboardEvent('keydown', {
                key: char,
                bubbles: true
            }));
        }
        
        log(`消息已输入: ${message.substring(0, 50)}${message.length > 50 ? '...' : ''}`, 'debug');
        return true;
    } catch (error) {
        log(`输入消息失败: ${error.message}`, 'error');
        return false;
    }
}

// 获取发送按钮
function getSendButton() {
    const selectors = [
        'button.Button.send.main-button.default.secondary.round.click-allowed',
        'button.Button.send.main-button',
        'button[aria-label="Send Message"]',
        'button[title="Send Message"]',
        'button.Button.main-button',
        '[data-testid="send-button"]'
    ];
    
    for (const selector of selectors) {
        const elements = document.querySelectorAll(selector);
        for (const element of elements) {
            if (element.offsetParent !== null) {
                log(`找到发送按钮: ${selector}`, 'debug');
                return element;
            }
        }
    }
    
    log('未找到发送按钮', 'error');
    return null;
}

// 检查按钮状态
function checkButtonState() {
    const recordButton = document.querySelector('button.Button.record.main-button.default.secondary.round.click-allowed');
    const sendButton = document.querySelector('button.Button.send.main-button.default.secondary.round.click-allowed');
    
    return {
        hasRecord: !!recordButton,
        hasSend: !!sendButton,
        recordVisible: recordButton && recordButton.offsetParent !== null,
        sendVisible: sendButton && sendButton.offsetParent !== null
    };
}

// 等待按钮状态变化
async function waitForSendButton() {
    log('开始监控按钮状态变化...', 'info');
    
    const startTime = Date.now();
    
    while (Date.now() - startTime < testConfig.maxWaitTime) {
        const buttonState = checkButtonState();
        
        log(`按钮状态 - Record: ${buttonState.hasRecord}(${buttonState.recordVisible}) Send: ${buttonState.hasSend}(${buttonState.sendVisible})`, 'debug');
        
        if (buttonState.hasSend && buttonState.sendVisible) {
            log('检测到send按钮状态，准备点击', 'success');
            await sleep(testConfig.sendDelay);
            return getSendButton();
        }
        
        await sleep(testConfig.buttonCheckInterval);
    }
    
    log('等待按钮状态变化超时', 'error');
    return null;
}

// 点击发送按钮
async function clickSendButton(button) {
    try {
        if (!button || button.offsetParent === null) {
            log('按钮不可见或不存在', 'error');
            return false;
        }
        
        button.focus();
        button.click();
        
        log('发送按钮已点击', 'success');
        return true;
    } catch (error) {
        log(`点击发送按钮失败: ${error.message}`, 'error');
        return false;
    }
}

// 获取消息元素
function getMessageElements() {
    const messageElements = document.querySelectorAll('[id^="message-"]');
    log(`找到 ${messageElements.length} 个消息元素`, 'debug');
    return Array.from(messageElements);
}

// 从消息ID中提取数字
function extractMessageNumber(messageId) {
    const match = messageId.match(/message-(\d+)/);
    return match ? parseInt(match[1]) : 0;
}

// 获取消息ID集合，按数字排序
function getMessageIds() {
    const messageElements = getMessageElements();
    const ids = messageElements.map(el => el.id);
    
    ids.sort((a, b) => extractMessageNumber(a) - extractMessageNumber(b));
    
    log(`当前消息ID (按时间排序): [${ids.join(', ')}]`, 'debug');
    return new Set(ids);
}

// 检测新出现的消息
function detectNewMessages(previousIds) {
    const currentIds = getMessageIds();
    const newIds = [...currentIds].filter(id => !previousIds.has(id));
    
    if (newIds.length > 0) {
        newIds.sort((a, b) => extractMessageNumber(a) - extractMessageNumber(b));
        
        log(`检测到新消息ID (按时间排序): [${newIds.join(', ')}]`, 'success');
        return newIds.map(id => document.getElementById(id));
    }
    
    return [];
}

// 删除消息元素
function removeMessageElement(messageElement) {
    try {
        if (messageElement && messageElement.remove) {
            const messageId = messageElement.id;
            const messageNumber = extractMessageNumber(messageId);
            
            messageElement.remove();
            log(`已删除消息: ${messageId} (数字: ${messageNumber})`, 'debug');
            return true;
        } else {
            log('消息元素无效，无法删除', 'warning');
            return false;
        }
    } catch (error) {
        log(`删除消息元素失败: ${error.message}`, 'error');
        return false;
    }
}

// 检查指定消息元素中是否有下一页按钮
function hasNextPageButton(messageElement = null) {
    try {
        let searchScope;
        
        if (messageElement) {
            searchScope = messageElement;
            log(`在消息元素 ${messageElement.id} 中查找下一页按钮`, 'debug');
        } else {
            const messageElements = getMessageElements();
            if (messageElements.length === 0) {
                log('未找到任何消息元素', 'debug');
                return null;
            }
            
            searchScope = messageElements[messageElements.length - 1];
            log(`在最新消息元素 ${searchScope.id} 中查找下一页按钮`, 'debug');
        }
        
        const nextPageElements = searchScope.querySelectorAll('span.inline-button-text');
        
        for (const element of nextPageElements) {
            const text = element.textContent || element.innerText || '';
            if (text.includes('下一页')) {
                const emojiImg = element.querySelector('img[alt="♥️"], img[data-path*="2665.png"]');
                if (emojiImg) {
                    log('检测到下一页按钮（包含表情）', 'success');
                    return element;
                }
                log('检测到下一页按钮（不含表情）', 'info');
                return element;
            }
        }
        
        log('在当前消息元素中未发现下一页按钮', 'debug');
        return null;
        
    } catch (error) {
        log(`检查下一页按钮失败: ${error.message}`, 'error');
        return null;
    }
}

// 点击下一页按钮
async function clickNextPage(messageElement = null) {
    try {
        const nextPageButton = hasNextPageButton(messageElement);
        if (!nextPageButton) {
            log('没有找到下一页按钮', 'warning');
            return false;
        }
        
        log('找到下一页按钮，开始查找可点击元素...', 'debug');
        
        let clickableElement = null;
        
        let parent = nextPageButton;
        let level = 0;
        while (parent && level < 10) {
            if (parent.tagName === 'BUTTON') {
                clickableElement = parent;
                log(`找到BUTTON父级: ${parent.tagName}`, 'debug');
                break;
            }
            parent = parent.parentElement;
            level++;
        }
        
        if (!clickableElement) {
            clickableElement = nextPageButton;
            log('使用下一页按钮元素本身进行点击', 'debug');
        }
        
        if (clickableElement) {
            log(`准备使用强力点击方法: ${clickableElement.tagName}.${clickableElement.className || '无类名'}`, 'info');
            
            await sleep(150);
            
            const clickSuccess = await superForceClick(clickableElement);
            
            await sleep(200);
            
            if (clickSuccess) {
                log('下一页按钮点击成功', 'success');
                return true;
            } else {
                log('下一页按钮点击失败', 'error');
                return false;
            }
        } else {
            log('未找到任何可点击的元素', 'error');
            return false;
        }
        
    } catch (error) {
        log(`点击下一页按钮失败: ${error.message}`, 'error');
        return false;
    }
}

// 强力点击函数
async function superForceClick(element) {
    if (!element) {
        log('点击元素为空', 'error');
        return false;
    }
    
    try {
        element.scrollIntoView({ behavior: 'instant', block: 'center' });
        await sleep(100);
        
        const rect = element.getBoundingClientRect();
        const centerX = rect.left + rect.width / 2;
        const centerY = rect.top + rect.height / 2;
        
        log(`准备点击元素: ${element.tagName}.${element.className || '无类名'}`, 'debug');
        log(`点击坐标: (${centerX}, ${centerY})`, 'debug');
        
        const events = ['mousedown', 'mouseup', 'click'];
        for (const eventType of events) {
            const event = new MouseEvent(eventType, {
                view: window,
                bubbles: true,
                cancelable: true,
                clientX: centerX,
                clientY: centerY,
                button: 0,
                buttons: eventType === 'mousedown' ? 1 : 0
            });
            element.dispatchEvent(event);
            
            if (eventType !== 'click') {
                await sleep(25);
            }
        }
        
        log('完整点击流程模拟成功', 'success');
        return true;
        
    } catch (error) {
        log(`强力点击失败: ${error.message}`, 'error');
        return false;
    }
}

// 提取消息内容
function extractMessageContent(messageElement) {
    if (!messageElement) return '';
    
    const contentSelectors = [
        '.text-content',
        '.message-text',
        '.text',
        '[data-testid="message-text"]'
    ];
    
    for (const selector of contentSelectors) {
        const contentElement = messageElement.querySelector(selector);
        if (contentElement) {
            const content = contentElement.textContent || contentElement.innerText || '';
            if (content.trim()) {
                log(`提取到消息内容 (${selector}): ${content.substring(0, 100)}...`, 'debug');
                return content.trim();
            }
        }
    }
    
    const content = messageElement.textContent || messageElement.innerText || '';
    log(`使用默认方式提取内容: ${content.substring(0, 100)}...`, 'debug');
    return content.trim();
}

// 检查Telegram连接状态
function checkTelegramConnection() {
    try {
        const errorElements = document.querySelectorAll('.error, .connection-error, .offline');
        if (errorElements.length > 0) {
            log('检测到连接错误元素', 'warning');
            return false;
        }
        
        const connectingElements = document.querySelectorAll('[class*="connecting"], [class*="reconnect"]');
        if (connectingElements.length > 0) {
            log('检测到连接状态元素', 'warning');
            return false;
        }
        
        const chatContainer = document.querySelector('.messages-container, .chat-container, #MiddleColumn');
        if (!chatContainer) {
            log('未找到聊天容器，页面可能未完全加载', 'warning');
            return false;
        }
        
        const inputBox = getInputBox();
        if (!inputBox) {
            log('输入框不可用', 'warning');
            return false;
        }
        
        return true;
    } catch (error) {
        log(`连接状态检查失败: ${error.message}`, 'error');
        return false;
    }
}

// 等待Telegram连接恢复
async function waitForConnection(maxWaitTime = 30000) {
    log('正在等待Telegram连接恢复...', 'info');
    
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWaitTime) {
        if (checkTelegramConnection()) {
            log('Telegram连接正常', 'success');
            return true;
        }
        
        if ((Date.now() - startTime) % 5000 < 1000) {
            log(`等待连接恢复中... (${Math.floor((Date.now() - startTime) / 1000)}s)`, 'info');
        }
        
        await sleep(500);
    }
    
    log('等待连接恢复超时', 'error');
    return false;
}

// 初始化检查
function initCheck() {
    log('=== Telegram Web 自动化测试初始化 ===', 'info');
    log(`当前URL: ${window.location.href}`, 'info');
    log(`页面标题: ${document.title}`, 'info');
    
    if (!window.location.href.includes('web.telegram.org')) {
        log('警告: 当前页面可能不是Telegram Web', 'warning');
    }
    
    log('检查Telegram连接状态...', 'info');
    const connectionOk = checkTelegramConnection();
    log(`连接状态: ${connectionOk ? '正常' : '异常'}`, connectionOk ? 'success' : 'error');
    
    if (!connectionOk) {
        log('检测到连接问题，建议等待连接恢复后再进行测试', 'warning');
        log('可以运行 waitForConnection() 等待连接恢复', 'info');
    }
    
    // 删除左侧栏
    log('正在删除左侧栏...', 'debug');
    const leftColumn = document.querySelector('#LeftColumn');
    if (leftColumn) {
        leftColumn.remove();
        log('左侧栏已删除', 'success');
    }
    
    const inputBox = getInputBox();
    const messageElements = getMessageElements();
    
    log(`输入框状态: ${inputBox ? '找到' : '未找到'}`, inputBox ? 'success' : 'error');
    log(`消息元素数量: ${messageElements.length}`, 'info');
    
    const buttonState = checkButtonState();
    log(`按钮状态 - Record: ${buttonState.hasRecord}, Send: ${buttonState.hasSend}`, 'info');
    
    log('=== 初始化检查完成 ===', 'info');
    
    return {
        inputBox: !!inputBox,
        messageCount: messageElements.length,
        buttonState: buttonState,
        connectionOk: connectionOk
    };
}

// 主发送函数
async function sendMessage(message) {
    const executionStart = Date.now();
    const executionLog = [];
    
    try {
        executionLog.push(`开始发送消息: ${message}`);
        log(`开始发送消息: ${message}`, 'info');
        
        // 1. 检查连接状态
        if (!checkTelegramConnection()) {
            executionLog.push('Telegram连接异常，尝试恢复...');
            log('Telegram连接异常，正在尝试等待恢复...', 'warning');
            
            const connectionRestored = await waitForConnection(testConfig.maxWaitTime);
            if (!connectionRestored) {
                const error = 'Telegram连接失败，无法发送消息';
                executionLog.push(`错误: ${error}`);
                throw new Error(error);
            }
            executionLog.push('连接已恢复');
        } else {
            executionLog.push('Telegram连接正常');
        }
        
        // 2. 获取输入框
        const inputBox = getInputBox();
        if (!inputBox) {
            const error = '未找到输入框';
            executionLog.push(`错误: ${error}`);
            throw new Error(error);
        }
        executionLog.push('输入框定位成功');
        
        // 3. 记录发送前的消息ID集合
        const initialMessageIds = getMessageIds();
        executionLog.push(`发送前消息ID数量: ${initialMessageIds.size}`);
        log(`发送前消息ID数量: ${initialMessageIds.size}`, 'debug');
        
        // 4. 输入消息
        if (!inputMessage(inputBox, message)) {
            const error = '输入消息失败';
            executionLog.push(`错误: ${error}`);
            throw new Error(error);
        }
        executionLog.push('消息输入完成');
        
        // 5. 等待发送按钮状态变化
        const sendButton = await waitForSendButton();
        if (!sendButton) {
            const error = '未找到可用的发送按钮';
            executionLog.push(`错误: ${error}`);
            throw new Error(error);
        }
        executionLog.push('发送按钮状态检测完成');
        
        // 6. 点击发送按钮
        if (!await clickSendButton(sendButton)) {
            const error = '点击发送按钮失败';
            executionLog.push(`错误: ${error}`);
            throw new Error(error);
        }
        executionLog.push('发送按钮点击成功');
        
        // 7. 消息监听和处理
        log('设置DOM变化监听器...', 'debug');
        executionLog.push('开始监听消息变化...');
        
        let sentMessageId = null;
        let sentMessageElement = null;
        let replyMessage = null;
        let replyContent = '';
        let messageProcessingComplete = false;
        
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE && 
                            node.id && 
                            node.id.startsWith('message-')) {
                            
                            const messageNumber = extractMessageNumber(node.id);
                            log(`DOM监听检测到新消息: ${node.id} (数字: ${messageNumber})`, 'success');
                            
                            if (!sentMessageId) {
                                // 识别为发送的消息
                                sentMessageId = node.id;
                                sentMessageElement = node;
                                executionLog.push(`检测到发送消息: ${sentMessageId}`);
                                log(`识别为发送消息: ${sentMessageId}`, 'info');
                                
                                // 延迟删除发送消息
                                setTimeout(() => {
                                    if (removeMessageElement(node)) {
                                        log('发送消息已删除', 'debug');
                                    }
                                }, 25);
                                
                            } else if (!messageProcessingComplete) {
                                // 识别为回复消息
                                replyMessage = node;
                                replyContent = extractMessageContent(node);
                                messageProcessingComplete = true;
                                
                                executionLog.push(`检测到回复消息: ${node.id}`);
                                executionLog.push(`回复内容: ${replyContent.substring(0, 100)}${replyContent.length > 100 ? '...' : ''}`);
                                
                                log(`识别为回复消息: ${node.id}`, 'info');
                                log(`回复内容: ${replyContent.substring(0, 100)}${replyContent.length > 100 ? '...' : ''}`, 'info');
                            }
                        }
                    });
                }
            });
        });
        
        const chatContainer = document.querySelector('#MiddleColumn, .messages-container, .chat-container');
        if (chatContainer) {
            observer.observe(chatContainer, {
                childList: true,
                subtree: true
            });
            log('DOM监听器已启动', 'debug');
            executionLog.push('DOM监听器启动成功');
        } else {
            log('未找到聊天容器，使用轮询检测', 'warning');
            executionLog.push('使用轮询检测模式');
            
            // 轮询检测模式
            const pollForMessages = async () => {
                for (let i = 0; i < 40; i++) {
                    const newMessages = detectNewMessages(initialMessageIds);
                    
                    if (newMessages.length > 0) {
                        const newMessage = newMessages[0];
                        
                        if (!sentMessageId) {
                            sentMessageId = newMessage.id;
                            sentMessageElement = newMessage;
                            executionLog.push(`轮询检测到发送消息: ${sentMessageId}`);
                            log(`轮询检测到发送消息: ${sentMessageId}`, 'info');
                            removeMessageElement(newMessage);
                        } else if (!messageProcessingComplete) {
                            replyMessage = newMessage;
                            replyContent = extractMessageContent(newMessage);
                            messageProcessingComplete = true;
                            
                            executionLog.push(`轮询检测到回复消息: ${newMessage.id}`);
                            executionLog.push(`回复内容: ${replyContent.substring(0, 100)}${replyContent.length > 100 ? '...' : ''}`);
                            
                            log(`轮询检测到回复消息: ${newMessage.id}`, 'info');
                            log(`回复内容: ${replyContent.substring(0, 100)}${replyContent.length > 100 ? '...' : ''}`, 'info');
                            break;
                        }
                    }
                    
                    await sleep(testConfig.contentCheckInterval);
                }
            };
            
            pollForMessages();
        }
        
        // 等待消息处理完成
        const waitStart = Date.now();
        while (Date.now() - waitStart < testConfig.maxWaitTime) {
            if (messageProcessingComplete && replyMessage && replyContent) {
                executionLog.push('消息处理完成');
                log('消息处理完成', 'success');
                break;
            }
            
            await sleep(testConfig.messageCheckDelay);
        }
        
        observer.disconnect();
        log('DOM监听器已停止', 'debug');
        
        const executionTime = Date.now() - executionStart;
        executionLog.push(`总执行时间: ${executionTime}ms`);
        
        // 构建返回结果
        const result = {
                success: true,
            message: '消息发送成功',
            data: {
                sentMessage: {
                    id: sentMessageId,
                    content: message,
                    timestamp: Date.now()
                },
                replyMessage: {
                    id: replyMessage ? replyMessage.id : null,
                    content: replyContent,
                    hasContent: !!replyContent,
                    timestamp: Date.now()
                },
                execution: {
                    duration: executionTime,
                    log: executionLog,
                    mode: chatContainer ? 'DOM监听' : '轮询检测'
                }
            },
            // 兼容旧版本
            content: replyContent,
            replyElement: replyMessage
        };
        
        if (!replyMessage) {
            result.message = '消息已发送，但未检测到回复';
            result.data.replyMessage.content = '';
            executionLog.push('警告: 未检测到回复消息');
            log('未检测到回复消息', 'warning');
        } else {
            // 清理回复消息元素
            setTimeout(() => {
                if (removeMessageElement(replyMessage)) {
                    log('回复消息已清理', 'debug');
                }
            }, 500);
        }
        
        log('消息发送完成!', 'success');
        return result;
        
    } catch (error) {
        const executionTime = Date.now() - executionStart;
        executionLog.push(`执行失败: ${error.message}`);
        executionLog.push(`总执行时间: ${executionTime}ms`);
        
        log(`发送消息失败: ${error.message}`, 'error');
        
        return {
            success: false,
            message: error.message,
            data: {
                sentMessage: null,
                replyMessage: null,
                execution: {
                    duration: executionTime,
                    log: executionLog,
                    error: error.message
                }
            },
            // 兼容旧版本
            content: '',
            replyElement: null
        };
    }
}

// 支持翻页功能的消息发送函数
async function sendMessageWithPagination(message, enablePagination = false) {
    const executionStart = Date.now();
    const executionLog = [];
    
    try {
        executionLog.push(`开始发送消息 (翻页${enablePagination ? '启用' : '禁用'}): ${message}`);
        log(`开始发送消息 (翻页${enablePagination ? '启用' : '禁用'}): ${message}`, 'info');
        
        // 首先执行标准发送流程，但不删除回复元素
        if (!checkTelegramConnection()) {
            executionLog.push('Telegram连接异常，尝试恢复...');
            log('Telegram连接异常，正在尝试等待恢复...', 'warning');
            
            const connectionRestored = await waitForConnection(testConfig.maxWaitTime);
            if (!connectionRestored) {
                const error = 'Telegram连接失败，无法发送消息';
                executionLog.push(`错误: ${error}`);
                throw new Error(error);
            }
            executionLog.push('连接已恢复');
        } else {
            executionLog.push('Telegram连接正常');
        }
        
        const inputBox = getInputBox();
        if (!inputBox) {
            const error = '未找到输入框';
            executionLog.push(`错误: ${error}`);
            throw new Error(error);
        }
        executionLog.push('输入框定位成功');
        
        const initialMessageIds = getMessageIds();
        executionLog.push(`发送前消息ID数量: ${initialMessageIds.size}`);
        log(`发送前消息ID数量: ${initialMessageIds.size}`, 'debug');
        
        if (!inputMessage(inputBox, message)) {
            const error = '输入消息失败';
            executionLog.push(`错误: ${error}`);
            throw new Error(error);
        }
        executionLog.push('消息输入完成');
        
        const sendButton = await waitForSendButton();
        if (!sendButton) {
            const error = '未找到可用的发送按钮';
            executionLog.push(`错误: ${error}`);
            throw new Error(error);
        }
        executionLog.push('发送按钮状态检测完成');
        
        if (!await clickSendButton(sendButton)) {
            const error = '点击发送按钮失败';
            executionLog.push(`错误: ${error}`);
            throw new Error(error);
        }
        executionLog.push('发送按钮点击成功');
        
        log('设置DOM变化监听器...', 'debug');
        executionLog.push('开始监听消息变化...');
        
        let sentMessageId = null;
        let sentMessageElement = null;
        let replyMessage = null;
        let content = '';
        let messageProcessingComplete = false;
        
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE && 
                            node.id && 
                            node.id.startsWith('message-')) {
                            
                            const messageNumber = extractMessageNumber(node.id);
                            log(`DOM监听检测到新消息: ${node.id} (数字: ${messageNumber})`, 'success');
                            
                            if (!sentMessageId) {
                                sentMessageId = node.id;
                                sentMessageElement = node;
                                executionLog.push(`检测到发送消息: ${sentMessageId}`);
                                log(`识别为发送消息: ${sentMessageId}`, 'info');
                                
                                setTimeout(() => {
                                    if (removeMessageElement(node)) {
                                        log('发送消息已删除', 'debug');
                                    }
                                }, 25);
                                
                            } else if (!messageProcessingComplete) {
                                replyMessage = node;
                                content = extractMessageContent(node);
                                messageProcessingComplete = true;
                                
                                executionLog.push(`检测到回复消息: ${node.id}`);
                                executionLog.push(`回复内容: ${content.substring(0, 100)}${content.length > 100 ? '...' : ''}`);
                                
                                log(`识别为回复消息: ${node.id}`, 'info');
                                log(`回复内容: ${content.substring(0, 100)}${content.length > 100 ? '...' : ''}`, 'info');
                            }
                        }
                    });
                }
            });
        });
        
        const chatContainer = document.querySelector('#MiddleColumn, .messages-container, .chat-container');
        if (chatContainer) {
            observer.observe(chatContainer, {
                childList: true,
                subtree: true
            });
            log('DOM监听器已启动', 'debug');
            executionLog.push('DOM监听器启动成功');
        } else {
            executionLog.push('使用轮询检测模式');
            
            // 轮询检测模式
            const pollForMessages = async () => {
                for (let i = 0; i < 40; i++) {
                    const newMessages = detectNewMessages(initialMessageIds);
                    
                    if (newMessages.length > 0) {
                        const newMessage = newMessages[0];
                        
                        if (!sentMessageId) {
                            sentMessageId = newMessage.id;
                            sentMessageElement = newMessage;
                            executionLog.push(`轮询检测到发送消息: ${sentMessageId}`);
                            log(`轮询检测到发送消息: ${sentMessageId}`, 'info');
                            removeMessageElement(newMessage);
                        } else if (!messageProcessingComplete) {
                            replyMessage = newMessage;
                            content = extractMessageContent(newMessage);
                            messageProcessingComplete = true;
                            
                            executionLog.push(`轮询检测到回复消息: ${newMessage.id}`);
                            executionLog.push(`回复内容: ${content.substring(0, 100)}${content.length > 100 ? '...' : ''}`);
                            
                            log(`轮询检测到回复消息: ${newMessage.id}`, 'info');
                            log(`回复内容: ${content.substring(0, 100)}${content.length > 100 ? '...' : ''}`, 'info');
                            break;
                        }
                    }
                    
                    await sleep(testConfig.contentCheckInterval);
                }
            };
            
            pollForMessages();
        }
        
        // 等待消息处理完成
        const waitStart = Date.now();
        while (Date.now() - waitStart < testConfig.maxWaitTime) {
            if (messageProcessingComplete && replyMessage && content) {
                executionLog.push('消息处理完成');
                log('消息处理完成', 'success');
                break;
            }
            await sleep(testConfig.messageCheckDelay);
        }
        
        observer.disconnect();
        log('DOM监听器已停止', 'debug');
        
        if (!replyMessage) {
            const executionTime = Date.now() - executionStart;
            executionLog.push('警告: 未检测到回复消息');
            executionLog.push(`总执行时间: ${executionTime}ms`);
            log('未检测到回复消息', 'warning');
            
            return {
                success: true,
                message: '消息已发送，但未检测到回复',
                data: {
                    sentMessage: {
                        id: sentMessageId,
                        content: message,
                        timestamp: Date.now()
                    },
                    replyMessage: {
                        id: null,
                        content: '',
                        hasContent: false,
                        timestamp: Date.now()
                    },
                    pagination: {
                        enabled: enablePagination,
                        pages: 0,
                        totalContent: ''
                    },
                    execution: {
                        duration: executionTime,
                        log: executionLog,
                        mode: chatContainer ? 'DOM监听' : '轮询检测'
                    }
                },
                // 兼容旧版本
                content: '',
                pages: 0
            };
        }
        
        let allContents = [];
        let currentPage = 1;
        let currentMessageElement = replyMessage;
        
        // 记录第一页内容
        if (content && content.trim()) {
            allContents.push({
                page: 1,
                content: content.trim()
            });
            executionLog.push(`记录第1页内容 (长度: ${content.trim().length})`);
            log(`记录第1页内容: ${content.substring(0, 100)}...`, 'success');
        }
        
        // 如果启用翻页功能
        if (enablePagination && currentMessageElement) {
            executionLog.push(`开始翻页处理，消息ID: ${currentMessageElement.id}`);
            log(`开始翻页处理，消息ID: ${currentMessageElement.id}`, 'info');
            
            let previousContent = content.trim();
            let maxPageAttempts = 50; // 最多50页
            
            // 循环翻页直到找不到下一页按钮
            while (hasNextPageButton(currentMessageElement) && currentPage < maxPageAttempts) {
                log(`准备翻页到第${currentPage + 1}页...`, 'info');
                
                // 点击前检测当前内容
                const beforeClickContent = extractMessageContent(currentMessageElement).trim();
                log(`点击前内容长度: ${beforeClickContent.length}`, 'debug');
                
                // 点击下一页按钮
                const pageClicked = await clickNextPage(currentMessageElement);
                if (!pageClicked) {
                    executionLog.push(`第${currentPage + 1}页点击失败`);
                    log(`第${currentPage + 1}页点击失败`, 'warning');
                    break;
                }
                
                // 点击后等待内容加载
                await sleep(testConfig.paginationDelay);
                
                // 点击后检测内容变化
                let contentChanged = false;
                let retryCount = 0;
                const maxRetries = 10;
                
                while (!contentChanged && retryCount < maxRetries) {
                    await sleep(testConfig.contentCheckInterval);
                    
                    const afterClickContent = extractMessageContent(currentMessageElement).trim();
                    
                    if (afterClickContent !== beforeClickContent && afterClickContent !== previousContent && afterClickContent) {
                        currentPage++;
                        allContents.push({
                            page: currentPage,
                            content: afterClickContent
                        });
                        
                        executionLog.push(`成功获取第${currentPage}页内容 (长度: ${afterClickContent.length})`);
                        log(`成功获取第${currentPage}页内容 (长度: ${afterClickContent.length})`, 'success');
                        log(`新内容预览: ${afterClickContent.substring(0, 100)}...`, 'info');
                        
                        previousContent = afterClickContent;
                        contentChanged = true;
                    } else {
                        retryCount++;
                        log(`第${retryCount}次检测内容未变化`, 'debug');
                    }
                }
                
                if (!contentChanged) {
                    executionLog.push(`第${currentPage + 1}页内容未变化，翻页可能失败`);
                    log(`第${currentPage + 1}页内容未变化，翻页可能失败`, 'warning');
                }
            }
            
            if (currentPage >= maxPageAttempts) {
                executionLog.push('达到最大页数限制，停止翻页');
                log('达到最大页数限制，停止翻页', 'warning');
            } else {
                executionLog.push('未找到下一页按钮，翻页完成');
                log('未找到下一页按钮，翻页完成', 'info');
            }
            
            executionLog.push(`翻页完成，总共获取 ${allContents.length} 页内容`);
            log(`翻页完成，总共获取 ${allContents.length} 页内容`, 'success');
        }
        
        // 合并所有页面内容
        let finalContent = '';
        if (allContents.length > 0) {
            finalContent = allContents.map((item, index) => {
                if (index === 0) {
                    return item.content;
                } else {
                    return `\n\n--- 第 ${item.page} 页 ---\n${item.content}`;
                }
            }).join('');
        }
        
        const executionTime = Date.now() - executionStart;
        executionLog.push(`总执行时间: ${executionTime}ms`);
        
        // 构建返回结果
        const result = {
            success: true,
            message: `消息发送成功${enablePagination ? `，获取 ${allContents.length} 页内容` : ''}`,
            data: {
                sentMessage: {
                    id: sentMessageId,
                    content: message,
                    timestamp: Date.now()
                },
                replyMessage: {
                    id: replyMessage.id,
                    content: finalContent,
                    hasContent: !!finalContent,
                    timestamp: Date.now()
                },
                pagination: {
                    enabled: enablePagination,
                    pages: allContents.length,
                    totalContent: finalContent,
                    pageDetails: allContents
                },
                execution: {
                    duration: executionTime,
                    log: executionLog,
                    mode: chatContainer ? 'DOM监听' : '轮询检测'
                }
            },
            // 兼容旧版本
            content: finalContent,
            pages: allContents.length
        };
        
        // 清理回复消息元素
        if (currentMessageElement) {
            setTimeout(() => {
                if (removeMessageElement(currentMessageElement)) {
                    log('回复消息已清理', 'debug');
                }
            }, 500);
        }
        
        return result;
        
    } catch (error) {
        const executionTime = Date.now() - executionStart;
        executionLog.push(`执行失败: ${error.message}`);
        executionLog.push(`总执行时间: ${executionTime}ms`);
        
        log(`发送消息（翻页）失败: ${error.message}`, 'error');
        
        return {
            success: false,
            message: error.message,
            data: {
                sentMessage: null,
                replyMessage: null,
                pagination: {
                    enabled: enablePagination,
                    pages: 0,
                    totalContent: ''
                },
                execution: {
                    duration: executionTime,
                    log: executionLog,
                    error: error.message
                }
            },
            // 兼容旧版本
            content: '',
            pages: 0
        };
    }
}

// 确保核心函数在全局作用域中可用
window.sendMessageWithPagination = sendMessageWithPagination;
window.sendMessage = sendMessage;
window.extractMessageContent = extractMessageContent;
window.getMessageElements = getMessageElements;
window.checkTelegramConnection = checkTelegramConnection;
window.initCheck = initCheck;

// 记录函数导出状态
console.log('[Telegram测试工具] 全局函数注册完成，现在可以使用以下函数:');
console.log('- sendMessageWithPagination(消息, 是否启用翻页)');
console.log('- sendMessage(消息)');
console.log('- checkTelegramConnection()');
console.log('- initCheck()');

// 导出函数可用性验证
if (typeof window.sendMessageWithPagination === 'function') {
    console.log('[Telegram测试工具] sendMessageWithPagination函数已成功导出到全局作用域');
} else {
    console.error('[Telegram测试工具] 警告: sendMessageWithPagination函数未能成功导出');
}

// 修复Service Worker通知问题
if (typeof self !== 'undefined' && !self.registration) {
    self.registration = {
        getNotifications: function() {
            console.log('[Telegram测试工具] 模拟self.registration.getNotifications方法被调用');
            return Promise.resolve([]);
        }
    };
    console.log('[Telegram测试工具] 已添加模拟的self.registration.getNotifications方法');
} else if (typeof self !== 'undefined' && self.registration && !self.registration.getNotifications) {
    self.registration.getNotifications = function() {
        console.log('[Telegram测试工具] 模拟self.registration.getNotifications方法被调用');
        return Promise.resolve([]);
    };
    console.log('[Telegram测试工具] 已添加模拟的self.registration.getNotifications方法');
}

// 同时处理window对象
if (typeof window !== 'undefined' && !window.registration) {
    window.registration = {
        getNotifications: function() {
            console.log('[Telegram测试工具] 模拟window.registration.getNotifications方法被调用');
            return Promise.resolve([]);
        }
    };
    console.log('[Telegram测试工具] 已添加模拟的window.registration.getNotifications方法');
} else if (typeof window !== 'undefined' && window.registration && !window.registration.getNotifications) {
    window.registration.getNotifications = function() {
        console.log('[Telegram测试工具] 模拟window.registration.getNotifications方法被调用');
        return Promise.resolve([]);
    };
    console.log('[Telegram测试工具] 已添加模拟的window.registration.getNotifications方法');
}

// 添加全局错误处理程序
if (typeof window !== 'undefined') {
    // 保存原始的错误处理程序
    const originalOnError = window.onerror;
    
    // 设置新的错误处理程序
    window.onerror = function(message, source, lineno, colno, error) {
        // 检查是否是pushNotification.ts相关错误
        if (source && source.includes('pushNotification.ts')) {
            console.log('[Telegram测试工具] 捕获到pushNotification.ts错误:', message);
            console.log('[Telegram测试工具] 位置:', source, lineno, colno);
            
            // 防止错误冒泡
            return true;
        }
        
        // 调用原始处理程序
        if (originalOnError) {
            return originalOnError.apply(this, arguments);
        }
        
        // 默认行为
        return false;
    };
    
    // 处理Promise错误
    window.addEventListener('unhandledrejection', function(event) {
        const error = event.reason;
        if (error && error.stack && error.stack.includes('pushNotification.ts')) {
            console.log('[Telegram测试工具] 捕获到pushNotification.ts未处理的Promise错误:', error.message);
            console.log('[Telegram测试工具] 错误堆栈:', error.stack);
            
            // 防止错误冒泡
            event.preventDefault();
            event.stopPropagation();
        }
    });
    
    console.log('[Telegram测试工具] 已添加全局错误处理程序');
}

// 自动执行初始化
log('Telegram Web 自动化测试代码已加载!', 'success');
log('正在执行初始化检查...', 'info');

setTimeout(() => {
    try {
        const initResult = initCheck();
        
        if (initResult.inputBox && initResult.connectionOk) {
            log('系统初始化成功，可以开始测试', 'success');
            log('使用 sendMessage("测试消息") 发送消息', 'info');
            log('使用 sendMessageWithPagination("消息", true) 发送消息并翻页', 'info');
        } else if (!initResult.connectionOk) {
            log('Telegram连接异常，请等待连接恢复', 'warning');
            log('可以运行 waitForConnection() 等待连接恢复', 'info');
            log('或者刷新页面重新登录', 'warning');
        } else {
            log('初始化检查发现问题，请检查页面状态', 'warning');
            log('确保已登录Telegram Web并打开聊天窗口', 'warning');
        }
    } catch (error) {
        log(`初始化失败: ${error.message}`, 'error');
        log('请手动执行 initCheck() 查看详情', 'warning');
    }
}, 500); 
