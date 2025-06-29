/**
 * 消息队列批处理系统
 * 提供针对sendMessageWithPagination的队列化批处理功能
 */

// 消息队列
const messageQueue = [];

// 当前序号计数器
let currentSequenceNumber = 1;

// 队列配置
const queueConfig = {
    maxSize: 1000,       // 最大队列大小
    processDelay: 500,   // 处理间隔(毫秒)
    autoProcess: false,  // 是否自动处理
    isProcessing: false, // 是否正在处理
    enablePagination: true, // 默认启用翻页
    retryCount: 3,       // 失败重试次数
    retryDelay: 2000     // 重试延迟(毫秒)
};

// 处理结果历史
const processHistory = [];

/**
 * 添加消息到队列
 * 
 * @param {string} message - 要发送的消息
 * @param {boolean} enablePagination - 是否启用翻页，默认使用全局配置
 * @param {Object} metadata - 附加元数据
 * @returns {Object} - 添加结果
 */
function addToQueue(message, enablePagination = null, metadata = {}) {
    if (!message || typeof message !== 'string') {
        console.error('添加队列失败: 消息不能为空且必须为字符串');
        return {
            success: false,
            message: '消息不能为空且必须为字符串'
        };
    }
    
    // 创建队列项
    const queueItem = {
        id: Date.now() + Math.random().toString(36).substr(2, 5),
        seqNum: currentSequenceNumber++,
        message: message,
        enablePagination: enablePagination !== null ? enablePagination : queueConfig.enablePagination,
        metadata: metadata,
        timestamp: Date.now(),
        status: 'pending',
        retryCount: 0,
        result: null
    };
    
    // 添加到队列
    messageQueue.push(queueItem);
    
    console.info(`[队列系统] 添加消息到队列 #${queueItem.seqNum}: ${message.substring(0, 50)}${message.length > 50 ? '...' : ''}`);
    
    // 限制队列大小
    if (messageQueue.length > queueConfig.maxSize) {
        const removed = messageQueue.shift();
        console.warn(`[队列系统] 队列超出最大大小，移除最早项 #${removed.seqNum}`);
    }
    
    // 如果启用了自动处理，开始处理队列
    if (queueConfig.autoProcess && !queueConfig.isProcessing) {
        processQueue();
    }
    
    return {
        success: true,
        message: `消息已添加到队列，序号: #${queueItem.seqNum}`,
        seqNum: queueItem.seqNum,
        queueLength: messageQueue.length
    };
}

/**
 * 批量添加消息到队列
 * 
 * @param {Array<string>} messages - 消息数组
 * @param {boolean} enablePagination - 是否启用翻页，默认使用全局配置
 * @param {Object} metadata - 附加元数据
 * @returns {Object} - 添加结果
 */
function bulkAddToQueue(messages, enablePagination = null, metadata = {}) {
    if (!Array.isArray(messages) || messages.length === 0) {
        console.error('批量添加队列失败: 消息数组不能为空');
        return {
            success: false,
            message: '消息数组不能为空'
        };
    }
    
    const startSeqNum = currentSequenceNumber;
    const addedItems = [];
    
    messages.forEach((message, index) => {
        if (typeof message === 'string' && message.trim()) {
            // 为每个消息创建独立的元数据副本，并添加索引信息
            const itemMetadata = { 
                ...metadata, 
                bulkIndex: index, 
                bulkTotal: messages.length 
            };
            
            const queueItem = {
                id: Date.now() + Math.random().toString(36).substr(2, 5) + index,
                seqNum: currentSequenceNumber++,
                message: message,
                enablePagination: enablePagination !== null ? enablePagination : queueConfig.enablePagination,
                metadata: itemMetadata,
                timestamp: Date.now(),
                status: 'pending',
                retryCount: 0,
                result: null
            };
            
            messageQueue.push(queueItem);
            addedItems.push({
                seqNum: queueItem.seqNum,
                message: message.substring(0, 30) + (message.length > 30 ? '...' : '')
            });
        }
    });
    
    console.info(`[队列系统] 批量添加 ${addedItems.length} 条消息到队列 (序号 #${startSeqNum} - #${currentSequenceNumber - 1})`);
    
    // 限制队列大小
    while (messageQueue.length > queueConfig.maxSize) {
        const removed = messageQueue.shift();
        console.warn(`[队列系统] 队列超出最大大小，移除最早项 #${removed.seqNum}`);
    }
    
    // 如果启用了自动处理，开始处理队列
    if (queueConfig.autoProcess && !queueConfig.isProcessing && addedItems.length > 0) {
        processQueue();
    }
    
    return {
        success: true,
        message: `已批量添加 ${addedItems.length} 条消息到队列`,
        startSeqNum: startSeqNum,
        endSeqNum: currentSequenceNumber - 1,
        addedCount: addedItems.length,
        addedItems: addedItems,
        queueLength: messageQueue.length
    };
}

/**
 * 处理队列
 * 
 * @param {number} limit - 处理的最大消息数量，0表示不限制
 * @returns {Promise<Object>} - 处理结果
 */
async function processQueue(limit = 0) {
    // 如果已经在处理中，则返回
    if (queueConfig.isProcessing) {
        console.warn('[队列系统] 队列正在处理中，跳过');
        return {
            success: false,
            message: '队列正在处理中',
            isProcessing: true
        };
    }
    
    // 检查队列是否为空
    if (messageQueue.length === 0) {
        console.info('[队列系统] 队列为空，无需处理');
        return {
            success: true,
            message: '队列为空',
            processedCount: 0
        };
    }
    
    console.info('========================================');
    console.info(`[队列系统] 开始处理队列 (${limit > 0 ? '限制 ' + limit + ' 条' : '不限制'})`);
    console.info('========================================');
    
    queueConfig.isProcessing = true;
    
    let processedCount = 0;
    let successCount = 0;
    let failedCount = 0;
    const results = [];
    
    try {
        // 获取待处理的消息
        const pendingItems = messageQueue.filter(item => item.status === 'pending' || item.status === 'failed');
        const itemsToProcess = limit > 0 ? pendingItems.slice(0, limit) : pendingItems;
        
        console.info(`[队列系统] 待处理: ${pendingItems.length} 条, 本次处理: ${itemsToProcess.length} 条`);
        
        // 逐个处理消息
        for (let i = 0; i < itemsToProcess.length; i++) {
            const item = itemsToProcess[i];
            
            // 更新状态为处理中
            item.status = 'processing';
            item.processingStartTime = Date.now();
            
            console.info('----------------------------------------');
            console.info(`[队列系统] 处理消息 #${item.seqNum} (${i+1}/${itemsToProcess.length})`);
            console.info(`[队列系统] 消息内容: ${item.message.substring(0, 50)}${item.message.length > 50 ? '...' : ''}`);
            console.info(`[队列系统] 翻页功能: ${item.enablePagination ? '启用' : '禁用'}`);
            
            try {
                // 检查全局变量中是否有sendMessageWithPagination函数
                if (typeof window.sendMessageWithPagination !== 'function') {
                    throw new Error('sendMessageWithPagination函数不可用，请确保console_test.js已加载');
                }
                
                // 调用sendMessageWithPagination函数
                console.info(`[队列系统] 开始执行sendMessageWithPagination...`);
                const sendResult = await window.sendMessageWithPagination(item.message, item.enablePagination);
                console.info(`[队列系统] 执行完成，结果: ${sendResult.success ? '成功' : '失败'}`);
                
                // 记录结果
                item.result = sendResult;
                item.processedAt = Date.now();
                
                if (sendResult.success) {
                    item.status = 'completed';
                    successCount++;
                    
                    // 输出结果摘要
                    console.info(`[队列系统] 消息 #${item.seqNum} 处理成功`);
                    if (sendResult.data && sendResult.data.pagination) {
                        console.info(`[队列系统] 获取页数: ${sendResult.data.pagination.pages}`);
                        console.info(`[队列系统] 内容长度: ${sendResult.data.replyMessage.content.length} 字符`);
                    }
                } else {
                    // 检查是否需要重试
                    if (item.retryCount < queueConfig.retryCount) {
                        item.status = 'retry';
                        item.retryCount++;
                        console.warn(`[队列系统] 消息 #${item.seqNum} 处理失败，准备第 ${item.retryCount} 次重试`);
                    
                        // 等待重试延迟
                        await new Promise(resolve => setTimeout(resolve, queueConfig.retryDelay));
                    
                        // 重新执行发送
                        console.info(`[队列系统] 重试执行 #${item.seqNum}...`);
                        const retryResult = await window.sendMessageWithPagination(item.message, item.enablePagination);
                        
                        item.result = retryResult;
                        item.processedAt = Date.now();
                    
                        if (retryResult.success) {
                            item.status = 'completed';
                            successCount++;
                            console.info(`[队列系统] 重试成功 #${item.seqNum}`);
                        } else {
                            item.status = 'failed';
                            failedCount++;
                            console.error(`[队列系统] 重试失败 #${item.seqNum}: ${retryResult.message}`);
                        }
                    } else {
                        item.status = 'failed';
                        failedCount++;
                        console.error(`[队列系统] 消息 #${item.seqNum} 处理失败: ${sendResult.message}`);
                    }
                }
            } catch (error) {
                // 处理异常
                item.status = 'failed';
                item.error = error.message;
                failedCount++;
                
                console.error(`[队列系统] 消息 #${item.seqNum} 处理异常: ${error.message}`);
            }
            
            // 添加到处理历史
            processHistory.push({
                seqNum: item.seqNum,
                message: item.message,
                status: item.status,
                timestamp: Date.now(),
                result: item.result
            });
            
            // 限制历史记录大小
            if (processHistory.length > 100) {
                processHistory.shift();
            }
            
            processedCount++;
            results.push({
                seqNum: item.seqNum,
                status: item.status,
                success: item.status === 'completed'
            });
            
            // 处理完一个消息后等待指定延迟，避免过快发送
            if (i < itemsToProcess.length - 1) {
                await new Promise(resolve => setTimeout(resolve, queueConfig.processDelay));
            }
        }
    } finally {
        // 重置处理状态
        queueConfig.isProcessing = false;
    }
    
    console.info('========================================');
    console.info(`[队列系统] 队列处理完成，共处理 ${processedCount} 条消息`);
    console.info(`[队列系统] 成功: ${successCount} 条, 失败: ${failedCount} 条`);
    console.info(`[队列系统] 队列剩余: ${messageQueue.filter(item => item.status === 'pending').length} 条待处理`);
    console.info('========================================');
    
    return {
        success: true,
        message: `队列处理完成，共处理 ${processedCount} 条消息`,
        processedCount: processedCount,
        successCount: successCount,
        failedCount: failedCount,
        results: results
    };
}

/**
 * 清空队列
 * 
 * @param {boolean} clearHistory - 是否同时清空历史记录
 * @returns {Object} - 清空结果
 */
function clearQueue(clearHistory = false) {
    const pendingCount = messageQueue.filter(item => item.status === 'pending').length;
    const totalCount = messageQueue.length;
    
    // 如果正在处理，只清除待处理的消息
    if (queueConfig.isProcessing) {
        const beforeCount = messageQueue.length;
        
        // 保留非待处理状态的消息
        const remainingItems = messageQueue.filter(item => item.status !== 'pending');
        messageQueue.length = 0;
        messageQueue.push(...remainingItems);
        
        const afterCount = messageQueue.length;
        const removedCount = beforeCount - afterCount;
        
        console.info(`[队列系统] 队列部分清空，移除了 ${removedCount} 条待处理消息，保留 ${afterCount} 条处理中/已完成消息`);
        
        if (clearHistory) {
            processHistory.length = 0;
            console.info('[队列系统] 历史记录已清空');
        }
        
        return {
            success: true,
            message: `队列部分清空，移除了 ${removedCount} 条待处理消息`,
            removedCount: removedCount,
            remainingCount: afterCount,
            isProcessing: true
        };
    } else {
        // 完全清空队列
    const count = messageQueue.length;
    messageQueue.length = 0;
        
        if (clearHistory) {
            processHistory.length = 0;
            console.info('[队列系统] 历史记录已清空');
        }
        
        console.info(`[队列系统] 队列已完全清空，共清除 ${count} 条消息`);
        
        return {
            success: true,
            message: `队列已完全清空，共清除 ${count} 条消息`,
            removedCount: count,
            remainingCount: 0,
            isProcessing: false
        };
    }
}

/**
 * 获取队列状态
 * 
 * @param {boolean} includeItems - 是否包含队列项详情
 * @returns {Object} - 队列状态
 */
function getQueueStatus(includeItems = false) {
    // 计算各状态消息数量
    const pending = messageQueue.filter(m => m.status === 'pending').length;
    const processing = messageQueue.filter(m => m.status === 'processing').length;
    const completed = messageQueue.filter(m => m.status === 'completed').length;
    const failed = messageQueue.filter(m => m.status === 'failed').length;
    const retry = messageQueue.filter(m => m.status === 'retry').length;
            
    const status = {
        total: messageQueue.length,
        pending: pending,
        processing: processing,
        completed: completed,
        failed: failed,
        retry: retry,
        config: { ...queueConfig },
        isProcessing: queueConfig.isProcessing,
        currentSequenceNumber: currentSequenceNumber
    };
    
    // 如果需要包含队列项详情
    if (includeItems) {
        status.items = messageQueue.map(item => ({
            seqNum: item.seqNum,
            message: item.message.substring(0, 50) + (item.message.length > 50 ? '...' : ''),
            status: item.status,
            timestamp: item.timestamp,
            processedAt: item.processedAt || null,
            retryCount: item.retryCount
        }));
    }
    
    return status;
}

/**
 * 获取处理历史
 * 
 * @param {number} limit - 获取的历史记录数量限制
 * @param {boolean} includeResults - 是否包含完整结果
 * @returns {Array} - 历史记录数组
 */
function getProcessHistory(limit = 0, includeResults = false) {
    let history = [...processHistory];
    
    // 限制返回数量
    if (limit > 0 && history.length > limit) {
        history = history.slice(-limit);
    }
    
    // 如果不包含完整结果，则精简结果对象
    if (!includeResults) {
        history = history.map(item => {
            const simplifiedItem = { ...item };
            
            if (simplifiedItem.result) {
                // 只保留结果的基本信息
                simplifiedItem.result = {
                    success: item.result.success,
                    message: item.result.message,
                    pages: item.result.pages || (item.result.data && item.result.data.pagination ? item.result.data.pagination.pages : 0),
                    contentLength: item.result.content ? item.result.content.length : 
                        (item.result.data && item.result.data.replyMessage ? item.result.data.replyMessage.content.length : 0)
                };
            }
            
            return simplifiedItem;
        });
    }
    
    return history;
}

/**
 * 设置队列配置
 * 
 * @param {Object} config - 配置对象
 * @returns {Object} - 更新后的配置
 */
function setQueueConfig(config) {
    if (typeof config !== 'object') {
        console.error('[队列系统] 无效的配置对象');
        return queueConfig;
    }
    
    // 更新配置
    if (typeof config.maxSize === 'number') queueConfig.maxSize = config.maxSize;
    if (typeof config.processDelay === 'number') queueConfig.processDelay = config.processDelay;
    if (typeof config.autoProcess === 'boolean') queueConfig.autoProcess = config.autoProcess;
    if (typeof config.enablePagination === 'boolean') queueConfig.enablePagination = config.enablePagination;
    if (typeof config.retryCount === 'number') queueConfig.retryCount = config.retryCount;
    if (typeof config.retryDelay === 'number') queueConfig.retryDelay = config.retryDelay;
    
    console.info('[队列系统] 队列配置已更新:', queueConfig);
    
    // 如果启用了自动处理，并且队列中有待处理的消息，则开始处理
    if (queueConfig.autoProcess && !queueConfig.isProcessing && 
        messageQueue.some(item => item.status === 'pending')) {
        console.info('[队列系统] 自动处理已启用，开始处理队列');
        processQueue();
    }
    
    return { ...queueConfig };
}

/**
 * 重置序号计数器
 * 
 * @param {number} newValue - 新的序号值，默认为1
 * @returns {Object} - 重置结果
 */
function resetSequenceNumber(newValue = 1) {
    const oldValue = currentSequenceNumber;
    currentSequenceNumber = newValue;
    
    console.info(`[队列系统] 序号计数器已重置: ${oldValue} -> ${newValue}`);
    
    return {
        success: true,
        message: `序号计数器已重置: ${oldValue} -> ${newValue}`,
        oldValue: oldValue,
        newValue: newValue
    };
}

/**
 * 获取队列中的特定项
 * 
 * @param {number} seqNum - 序号
 * @returns {Object|null} - 队列项或null
 */
function getQueueItem(seqNum) {
    const item = messageQueue.find(item => item.seqNum === seqNum);
    
    if (!item) {
        return null;
    }
    
    return {
        seqNum: item.seqNum,
        message: item.message,
        enablePagination: item.enablePagination,
        status: item.status,
        timestamp: item.timestamp,
        processedAt: item.processedAt || null,
        retryCount: item.retryCount,
        result: item.result
    };
}

/**
 * 删除队列中的特定项
 * 
 * @param {number} seqNum - 序号
 * @returns {Object} - 删除结果
 */
function removeQueueItem(seqNum) {
    const index = messageQueue.findIndex(item => item.seqNum === seqNum);
    
    if (index === -1) {
        return {
            success: false,
            message: `未找到序号为 ${seqNum} 的队列项`
        };
    }
    
    // 如果项目正在处理中，不允许删除
    if (messageQueue[index].status === 'processing') {
        return {
            success: false,
            message: `序号为 ${seqNum} 的队列项正在处理中，无法删除`
        };
    }
    
    // 删除项目
    const removedItem = messageQueue.splice(index, 1)[0];
    
    console.info(`[队列系统] 已删除队列项 #${seqNum}`);
    
    return {
        success: true,
        message: `已删除队列项 #${seqNum}`,
        item: {
            seqNum: removedItem.seqNum,
            message: removedItem.message.substring(0, 50) + (removedItem.message.length > 50 ? '...' : ''),
            status: removedItem.status
        }
    };
}

// 导出函数
window.MessageQueue = {
    add: addToQueue,
    bulkAdd: bulkAddToQueue,
    process: processQueue,
    clear: clearQueue,
    getStatus: getQueueStatus,
    setConfig: setQueueConfig,
    getHistory: getProcessHistory,
    resetSequence: resetSequenceNumber,
    getItem: getQueueItem,
    removeItem: removeQueueItem
};

// 初始化日志
console.info('========================================');
console.info('[队列系统] 消息队列批处理系统初始化完成');
console.info('========================================');
console.info('[队列系统] 可用方法:');
console.info('1. MessageQueue.add(message, enablePagination, metadata)');
console.info('   - message: 字符串，要发送的消息');
console.info('   - enablePagination: 布尔值，可选，是否启用翻页');
console.info('   - metadata: 对象，可选，附加元数据');
console.info('   - 返回: 添加结果，包含序号');
console.info('2. MessageQueue.bulkAdd(messages, enablePagination, metadata)');
console.info('   - messages: 字符串数组，要发送的多条消息');
console.info('   - enablePagination: 布尔值，可选，是否启用翻页');
console.info('   - metadata: 对象，可选，附加元数据');
console.info('   - 返回: 批量添加结果，包含序号范围');
console.info('3. MessageQueue.process(limit)');
console.info('   - limit: 数字，可选，处理的最大消息数量，0表示不限制');
console.info('   - 返回: Promise，处理结果');
console.info('4. MessageQueue.clear(clearHistory)');
console.info('   - clearHistory: 布尔值，可选，是否同时清空历史记录');
console.info('   - 返回: 清空结果');
console.info('5. MessageQueue.getStatus(includeItems)');
console.info('   - includeItems: 布尔值，可选，是否包含队列项详情');
console.info('   - 返回: 队列状态对象');
console.info('6. MessageQueue.setConfig(config)');
console.info('   - config: 对象，配置参数');
console.info('   - 返回: 更新后的配置对象');
console.info('7. MessageQueue.getHistory(limit, includeResults)');
console.info('   - limit: 数字，可选，获取的历史记录数量限制');
console.info('   - includeResults: 布尔值，可选，是否包含完整结果');
console.info('   - 返回: 历史记录数组');
console.info('8. MessageQueue.resetSequence(newValue)');
console.info('   - newValue: 数字，可选，新的序号值，默认为1');
console.info('   - 返回: 重置结果');
console.info('9. MessageQueue.getItem(seqNum)');
console.info('   - seqNum: 数字，序号');
console.info('   - 返回: 队列项或null');
console.info('10. MessageQueue.removeItem(seqNum)');
console.info('   - seqNum: 数字，序号');
console.info('   - 返回: 删除结果');
console.info('========================================');
console.info('使用示例:');
console.info('// 添加单条消息');
console.info('MessageQueue.add("你好，这是一条测试消息", true);');
console.info('');
console.info('// 批量添加消息');
console.info('MessageQueue.bulkAdd(["消息1", "消息2", "消息3"], true);');
console.info('');
console.info('// 开始处理队列');
console.info('MessageQueue.process();');
console.info('========================================'); 