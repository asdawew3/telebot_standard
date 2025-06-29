#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
控制台管理模块
负责与浏览器控制台交互，实现实时传输和命令执行
"""

import os
import sys
import time
import json
import threading
import traceback
from typing import Dict, Any, List, Optional, Callable, Union
from datetime import datetime

from .client_logger import get_client_logger, log_debug, log_info, log_error, log_warning, log_operation
from .client_api import ClientAPI

# 获取日志实例
logger = get_client_logger()

class ConsoleManager:
    """控制台管理类"""
    
    def __init__(self, client_api: Any):
        """
        初始化控制台管理器
        
        Args:
            client_api: 客户端API实例
        """
        logger.info("初始化控制台管理器", "__init__")
        
        # 保存API客户端
        self.client_api = client_api
        
        # DevTools管理器
        self.devtools_manager = None
        
        # 连接状态
        self.connected = False
        self.instance_id = None
        
        # 控制台缓冲区
        self.console_buffer = []
        self.max_buffer_size = 5000  # 增加缓冲区大小，从1000增加到5000
        
        # 命令历史
        self.command_history = []
        self.max_history_size = 100  # 最大历史记录大小
        
        # 线程安全
        self.command_lock = threading.Lock()
        
        # 轮询控制
        self.polling_thread = None
        self.stop_polling = threading.Event()
        self.polling_interval = 0.5  # 轮询间隔（秒）
        
        # 回调函数
        self.on_output = None  # 输出回调
        self.on_error = None   # 错误回调
        self.on_status_change = None  # 状态变更回调
        
        # 消息批处理控制
        self.batch_size = 50  # 每批发送的消息数量
        self.is_first_batch = True  # 标记是否是首次批量发送
        
        logger.debug("控制台管理器初始化完成", "__init__")
    
    def connect(self, instance_id: str) -> Dict[str, Any]:
        """
        连接到实例控制台
        
        Args:
            instance_id: 实例ID
            
        Returns:
            连接结果
        """
        logger.info(f"连接到实例控制台: {instance_id}", "connect")
        
        # 检查是否已连接
        if self.connected and self.instance_id == instance_id:
            logger.debug("已连接到该实例控制台，无需重复连接", "connect")
            return {
                'success': True,
                'message': '已连接到该实例控制台',
                'instance_id': instance_id
            }
        
        # 如果已连接到其他实例，先断开
        if self.connected and self.instance_id != instance_id:
            logger.debug(f"已连接到其他实例 {self.instance_id}，先断开", "connect")
            disconnect_result = self.disconnect()
            logger.debug(f"断开连接结果: {disconnect_result}", "connect")
        
        # 重置首次批量发送标记
        self.is_first_batch = True
        
        # 注意：此处不再清空控制台缓冲区，保留历史消息
        # 这样可以防止连接实例后控制台突然刷新、历史消息消失的问题
        
        # 重试参数
        max_retries = 2
        retry_delay = 2  # 秒
        
        for retry_count in range(max_retries + 1):  # +1是因为包括首次尝试
            try:
                # 记录重试信息
                if retry_count > 0:
                    logger.info(f"第 {retry_count} 次重试连接到实例控制台: {instance_id}", "connect")
                
                # 保存实例ID
                self.instance_id = instance_id
                
                # 创建DevTools管理器
                from .devtools_manager import DevToolsManager
                logger.debug("创建DevTools管理器", "connect")
                self.devtools_manager = DevToolsManager(self.client_api)
                
                # 设置DevTools回调
                logger.debug("设置DevTools回调函数", "connect")
                self.devtools_manager.set_callbacks(
                    on_message=self._on_devtools_message,
                    on_status_change=self._on_devtools_status_change,
                    on_error=self._on_devtools_error
                )
                
                # 首先确保实例已启用DevTools
                logger.info(f"确保实例已启用DevTools: {instance_id}", "connect")
                enable_result = self.client_api.enable_devtools(instance_id)
                
                if not enable_result.get('success'):
                    error_msg = enable_result.get('message', '未知错误')
                    error_code = enable_result.get('error_code', 'DEVTOOLS_ENABLE_ERROR')
                    logger.error(f"启用DevTools失败: {error_msg}", "connect")
                    logger.error(f"错误代码: {error_code}", "connect")
                    logger.error(f"错误详情: {enable_result}", "connect")
                    
                    # 获取更详细的错误信息
                    debugging_info = enable_result.get('debugging_info', {})
                    if debugging_info:
                        logger.error(f"调试信息: {debugging_info}", "connect")
                    
                    # 如果还有重试次数，则继续重试
                    if retry_count < max_retries:
                        logger.info(f"启用DevTools失败，将在 {retry_delay} 秒后重试", "connect")
                        
                        # 清理资源
                        self.instance_id = None
                        self.devtools_manager = None
                        
                        time.sleep(retry_delay)
                        continue
                    
                    # 所有重试都失败
                    logger.error(f"启用DevTools失败，已尝试 {retry_count + 1} 次", "connect")
                    
                    # 清理状态
                    self.instance_id = None
                    self.devtools_manager = None
                    
                    return {
                        'success': False,
                        'message': f'启用DevTools失败: {error_msg}',
                        'error_code': error_code,
                        'debugging_info': debugging_info,
                        'retries': retry_count
                    }
                
                logger.info(f"DevTools已启用: {instance_id}", "connect")
                
                # 连接到DevTools
                logger.info(f"连接到实例DevTools: {instance_id}", "connect")
                connect_result = self.devtools_manager.connect(instance_id)
                
                if not connect_result.get('success'):
                    error_msg = connect_result.get('message', '未知错误')
                    error_code = connect_result.get('error_code', 'DEVTOOLS_CONNECT_ERROR')
                    logger.error(f"连接到DevTools失败: {error_msg}", "connect")
                    logger.error(f"错误代码: {error_code}", "connect")
                    logger.error(f"错误详情: {connect_result}", "connect")
                    
                    # 获取更详细的错误信息
                    error_details = connect_result.get('error_details', {})
                    if error_details:
                        logger.error(f"错误详情: {error_details}", "connect")
                    
                    # 如果还有重试次数，则继续重试
                    if retry_count < max_retries:
                        logger.info(f"连接到DevTools失败，将在 {retry_delay} 秒后重试", "connect")
                        
                        # 清理资源
                        self.instance_id = None
                        self.devtools_manager = None
                        
                        time.sleep(retry_delay)
                        continue
                    
                    # 所有重试都失败
                    logger.error(f"连接到DevTools失败，已尝试 {retry_count + 1} 次", "connect")
                    
                    # 清理状态
                    self.instance_id = None
                    self.devtools_manager = None
                    
                    return {
                        'success': False,
                        'message': f'连接到DevTools失败: {error_msg}',
                        'error_code': error_code,
                        'error_details': error_details,
                        'retries': retry_count
                    }
                
                logger.info(f"DevTools连接成功: {instance_id}", "connect")
                logger.debug(f"DevTools连接详情: {connect_result}", "connect")
                
                # 初始化控制台
                logger.info("初始化控制台", "connect")
                init_result = self._initialize_console()
                
                if not init_result.get('success'):
                    error_msg = init_result.get('message', '未知错误')
                    error_code = init_result.get('error_code', 'CONSOLE_INIT_ERROR')
                    logger.error(f"初始化控制台失败: {error_msg}", "connect")
                    logger.error(f"错误代码: {error_code}", "connect")
                    logger.error(f"错误详情: {init_result}", "connect")
                    
                    # 如果还有重试次数，则继续重试
                    if retry_count < max_retries:
                        logger.info(f"初始化控制台失败，将在 {retry_delay} 秒后重试", "connect")
                        
                        # 断开DevTools连接
                        self.devtools_manager.disconnect()
                        
                        # 清理资源
                        self.instance_id = None
                        self.devtools_manager = None
                        self.connected = False
                        
                        time.sleep(retry_delay)
                        continue
                    
                    # 所有重试都失败
                    logger.error(f"初始化控制台失败，已尝试 {retry_count + 1} 次", "connect")
                    
                    # 断开DevTools连接
                    self.devtools_manager.disconnect()
                    
                    # 清理状态
                    self.instance_id = None
                    self.connected = False
                    
                    return {
                        'success': False,
                        'message': f'初始化控制台失败: {error_msg}',
                        'error_code': error_code,
                        'retries': retry_count
                    }
                
                # 添加系统消息
                self._add_system_message_to_buffer('info', '控制台连接成功')
                
                # 设置连接状态
                self.connected = True
                
                # 调用状态变更回调
                if self.on_status_change:
                    try:
                        logger.debug("调用状态变更回调", "connect")
                        self.on_status_change(True, instance_id)
                    except Exception as e:
                        logger.error("调用状态变更回调时发生异常", "connect", e)
                
                logger.info(f"控制台连接成功: {instance_id}", "connect")
                logger.operation("控制台连接成功", "connect", {
                    'instance_id': instance_id,
                    'retries': retry_count
                })
                
                return {
                    'success': True,
                    'message': '控制台连接成功',
                    'instance_id': instance_id,
                    'retries': retry_count
                }
                
            except Exception as e:
                logger.error("连接到实例控制台时发生异常", "connect", e)
                logger.error(f"异常详情: {str(e)}", "connect")
                logger.error(f"异常堆栈: {traceback.format_exc()}", "connect")
                
                # 如果还有重试次数，则继续重试
                if retry_count < max_retries:
                    logger.info(f"连接异常，将在 {retry_delay} 秒后重试", "connect")
                    
                    # 清理资源
                    self.instance_id = None
                    self.connected = False
                    
                    # 清理DevTools管理器
                    if self.devtools_manager:
                        try:
                            self.devtools_manager.disconnect()
                        except:
                            pass
                        self.devtools_manager = None
                    
                    time.sleep(retry_delay)
                    continue
                
                # 所有重试都失败
                logger.error(f"连接到实例控制台失败，已尝试 {retry_count + 1} 次", "connect")
                
                # 清理状态
                self.instance_id = None
                self.connected = False
                
                # 清理DevTools管理器
                if self.devtools_manager:
                    try:
                        self.devtools_manager.disconnect()
                    except:
                        pass
                    self.devtools_manager = None
                
                return {
                    'success': False,
                    'message': f'连接到实例控制台时发生异常: {str(e)}',
                    'error_code': 'CONSOLE_CONNECT_ERROR',
                    'exception': str(e),
                    'exception_type': type(e).__name__,
                    'retries': retry_count
                }
    
    def disconnect(self) -> Dict[str, Any]:
        """
        断开控制台连接
        
        Returns:
            断开结果
        """
        logger.info("断开控制台连接", "disconnect")
        
        # 保存当前连接信息
        prev_instance_id = self.instance_id
        
        # 重置状态
        self.connected = False
        self.instance_id = None
        
        # 断开DevTools连接
        if self.devtools_manager:
            try:
                logger.debug("断开DevTools连接", "disconnect")
                disconnect_result = self.devtools_manager.disconnect()
                
                if not disconnect_result.get('success'):
                    logger.warning(f"DevTools断开连接失败: {disconnect_result.get('message')}", "disconnect")
                else:
                    logger.debug("DevTools断开连接成功", "disconnect")
            except Exception as e:
                logger.error("断开DevTools连接时发生异常", "disconnect", e)
                logger.debug(f"异常详情: {str(e)}", "disconnect")
        else:
            logger.debug("DevTools管理器未初始化，无需断开连接", "disconnect")
        
        # 调用状态变更回调
        if self.on_status_change:
            try:
                logger.debug("调用状态变更回调", "disconnect")
                self.on_status_change(False, prev_instance_id)
                logger.debug("状态变更回调执行完成", "disconnect")
            except Exception as e:
                logger.error("调用状态变更回调时发生异常", "disconnect", e)
                logger.debug(f"异常详情: {str(e)}", "disconnect")
        
        logger.info("控制台已断开连接", "disconnect")
        logger.operation("控制台断开连接", "disconnect", {'instance_id': prev_instance_id})
        
        return {
            'success': True,
            'message': '控制台已断开连接'
        }
    
    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        执行控制台命令
        
        Args:
            command: 要执行的命令
            
        Returns:
            执行结果
        """
        logger.info(f"执行控制台命令: {command}", "execute_command")
        
        # 检查连接状态
        if not self.connected or not self.instance_id:
            logger.warning("控制台未连接，无法执行命令", "execute_command")
            logger.debug(f"控制台连接状态: connected={self.connected}, instance_id={self.instance_id}", "execute_command")
            return {
                'success': False,
                'message': '控制台未连接，无法执行命令'
            }
        
        try:
            # 添加到命令历史
            self._add_to_command_history(command)
            logger.debug("命令已添加到历史记录", "execute_command")
            
            # 检查DevTools管理器
            if not self.devtools_manager:
                logger.error("DevTools管理器未初始化，无法执行命令", "execute_command")
                return {
                    'success': False,
                    'message': 'DevTools管理器未初始化'
                }
            
            if not self.devtools_manager.connected:
                logger.error("DevTools未连接，无法执行命令", "execute_command")
                logger.debug(f"DevTools连接状态: {self.devtools_manager.connected}", "execute_command")
                return {
                    'success': False,
                    'message': 'DevTools未连接'
                }
            
            # 使用DevTools执行命令
            logger.debug("使用DevTools执行命令", "execute_command")
            logger.debug(f"DevTools执行参数: expression={command}, returnByValue=True, awaitPromise=True, generatePreview=True", "execute_command")
            
            start_time = time.time()
            result = self.devtools_manager.send_command('Runtime.evaluate', {
                'expression': command,
                'returnByValue': True,
                'awaitPromise': True,
                'generatePreview': True
            })
            execution_time = time.time() - start_time
            
            logger.debug(f"DevTools命令执行完成，耗时: {execution_time:.3f}秒", "execute_command")
            logger.debug(f"DevTools执行结果: {result}", "execute_command")
            
            if result.get('success'):
                # 提取执行结果
                eval_result = result.get('result', {})
                result_obj = eval_result.get('result', {})
                
                logger.debug(f"JavaScript执行结果对象: {result_obj}", "execute_command")
                
                # 处理执行结果
                if 'value' in result_obj:
                    # 基本类型值
                    value = result_obj.get('value')
                    result_value = value
                    logger.debug(f"基本类型结果值: {value}", "execute_command")
                elif 'preview' in result_obj:
                    # 对象预览
                    result_value = result_obj.get('preview', {})
                    logger.debug(f"对象预览结果: {result_value}", "execute_command")
                else:
                    # 其他情况
                    result_value = result_obj.get('description', 'undefined')
                    logger.debug(f"其他类型结果: {result_value}", "execute_command")
                    
                # 添加结果到缓冲区
                self._add_result_to_buffer(command, result_value)
                logger.debug("命令结果已添加到控制台缓冲区", "execute_command")
                
                logger.info(f"命令执行成功: {command}", "execute_command")
                logger.operation("控制台命令执行成功", "execute_command", {
                    'command': command,
                    'execution_time': execution_time,
                    'result_type': type(result_value).__name__
                })
                
                return {
                    'success': True,
                    'result': result_value,
                    'execution_time': execution_time
                }
            else:
                # 处理执行错误
                error_msg = result.get('message', '执行命令失败')
                error_code = result.get('error_code', 'UNKNOWN_ERROR')
                
                logger.warning(f"命令执行失败: {error_msg}", "execute_command")
                logger.debug(f"错误代码: {error_code}", "execute_command")
                logger.debug(f"错误详情: {result}", "execute_command")
                
                # 添加错误到缓冲区
                self._add_error_to_buffer(command, error_msg)
                logger.debug("错误信息已添加到控制台缓冲区", "execute_command")
                
                logger.operation("控制台命令执行失败", "execute_command", {
                    'command': command,
                    'error_message': error_msg,
                    'error_code': error_code
                })
                
                return {
                    'success': False,
                    'message': error_msg,
                    'error_code': error_code
                }
                
        except Exception as e:
            logger.error("执行命令时发生异常", "execute_command", e)
            logger.error(f"异常详情: {str(e)}", "execute_command")
            logger.error(f"异常堆栈: {traceback.format_exc()}", "execute_command")
            
            # 添加错误到缓冲区
            self._add_error_to_buffer(command, str(e))
            logger.debug("异常信息已添加到控制台缓冲区", "execute_command")
            
            logger.operation("控制台命令执行异常", "execute_command", {
                'command': command,
                'exception': str(e),
                'exception_type': type(e).__name__
            })
            
            return {
                'success': False,
                'message': f'执行命令时发生异常: {str(e)}',
                'error_code': 'EXECUTION_EXCEPTION',
                'exception': str(e),
                'exception_type': type(e).__name__
            }
    
    def _add_result_to_buffer(self, command: str, result: Any) -> None:
        """添加命令结果到缓冲区并通知前端"""
        logger.debug("开始添加命令结果到缓冲区", "_add_result_to_buffer")
        
        # 创建消息条目
        input_entry = {
            'type': 'input',
            'content': command,
            'timestamp': int(time.time() * 1000),
            'level': 'log'
        }
        result_entry = {
            'type': 'result',
            'content': str(result),
            'timestamp': int(time.time() * 1000),
            'level': 'log'
        }
        
        # 添加到缓冲区
        self.console_buffer.extend([input_entry, result_entry])
        logger.debug("已将命令输入和结果添加到缓冲区", "_add_result_to_buffer")
        
        # 保持缓冲区大小
        self._trim_buffer()
        logger.debug("缓冲区大小检查完成", "_add_result_to_buffer")
        
        # 调用输出回调
        if self.on_output:
            try:
                logger.debug("调用输出回调以广播结果", "_add_result_to_buffer")
                self.on_output([input_entry, result_entry])
                logger.debug("输出回调执行完成", "_add_result_to_buffer")
            except Exception as e:
                logger.error("调用输出回调时发生异常", "_add_result_to_buffer", e)
        else:
            logger.debug("未设置输出回调，结果未广播", "_add_result_to_buffer")
    
    def _add_error_to_buffer(self, command: str, error_message: str) -> None:
        """添加错误消息到缓冲区并通知前端"""
        logger.debug("开始添加错误消息到缓冲区", "_add_error_to_buffer")
        
        # 创建消息条目
        input_entry = {
            'type': 'input',
            'content': command,
            'timestamp': int(time.time() * 1000),
            'level': 'log'
        }
        error_entry = {
            'type': 'error',
            'content': error_message,
            'timestamp': int(time.time() * 1000),
            'level': 'error'
        }
        
        # 添加到缓冲区
        self.console_buffer.extend([input_entry, error_entry])
        logger.debug("已将命令输入和错误信息添加到缓冲区", "_add_error_to_buffer")
        
        # 保持缓冲区大小
        self._trim_buffer()
        logger.debug("缓冲区大小检查完成", "_add_error_to_buffer")
        
        # 调用输出回调
        if self.on_output:
            try:
                logger.debug("调用输出回调以广播错误", "_add_error_to_buffer")
                self.on_output([input_entry, error_entry])
                logger.debug("输出回调执行完成", "_add_error_to_buffer")
            except Exception as e:
                logger.error("调用输出回调时发生异常", "_add_error_to_buffer", e)
        else:
            logger.debug("未设置输出回调，错误未广播", "_add_error_to_buffer")
    
    def clear_console(self) -> Dict[str, Any]:
        """
        清空控制台
        
        Returns:
            清空结果
        """
        logger.info("清空控制台", "clear_console")
        
        # 检查连接状态
        if not self.connected or not self.instance_id:
            logger.warning("控制台未连接，无法清空", "clear_console")
            return {
                'success': False,
                'message': '控制台未连接，请先连接到实例'
            }
        
        # 使用锁确保线程安全
        with self.command_lock:
            try:
                # 执行清空命令
                result = self.client_api.execute_command(
                    self.instance_id,
                    'console.clear',
                    []
                )
                
                if result.get('success'):
                    # 清空本地缓冲区
                    self.console_buffer = []
                    
                    logger.info("控制台已清空", "clear_console")
                    logger.operation("控制台已清空", "clear_console", {'instance_id': self.instance_id})
                else:
                    logger.warning(f"清空控制台失败: {result.get('message')}", "clear_console")
                
                return result
            except Exception as e:
                logger.error("清空控制台时发生异常", "clear_console", e)
                return {
                    'success': False,
                    'message': f'清空控制台时发生异常: {str(e)}'
                }
    
    def get_command_history(self) -> List[str]:
        """
        获取命令历史
        
        Returns:
            命令历史列表
        """
        return self.command_history.copy()
    
    def set_callbacks(self, on_output: Optional[Callable] = None, 
                     on_status_change: Optional[Callable] = None,
                     on_error: Optional[Callable] = None) -> None:
        """
        设置回调函数
        
        Args:
            on_output: 输出回调函数
            on_status_change: 状态变更回调函数
            on_error: 错误回调函数
        """
        logger.debug("设置控制台回调函数", "set_callbacks")
        
        if on_output:
            self.on_output = on_output
            logger.debug("已设置输出回调函数", "set_callbacks")
        
        if on_status_change:
            self.on_status_change = on_status_change
            logger.debug("已设置状态变更回调函数", "set_callbacks")
        
        if on_error:
            self.on_error = on_error
            logger.debug("已设置错误回调函数", "set_callbacks")
    
    def _initialize_console(self) -> Dict[str, Any]:
        """
        初始化控制台连接
        
        Returns:
            初始化结果
        """
        logger.info(f"初始化控制台连接: {self.instance_id}", "_initialize_console")
        logger.debug(f"DevTools连接状态: {self.devtools_manager.connected}", "_initialize_console")
        
        try:
            # 1. 确保DevTools连接已建立
            if not self.devtools_manager or not self.devtools_manager.connected:
                logger.error("DevTools连接未建立，无法初始化控制台", "_initialize_console")
                logger.error(f"DevTools管理器: {self.devtools_manager}", "_initialize_console")
                if self.devtools_manager:
                    logger.error(f"DevTools连接状态: {self.devtools_manager.connected}", "_initialize_console")
                    logger.error(f"DevTools实例ID: {self.devtools_manager.instance_id}", "_initialize_console")
                    logger.error(f"DevTools WebSocket URL: {self.devtools_manager.ws_url}", "_initialize_console")
                
                return {
                    'success': False,
                    'message': '连接到DevTools失败: DevTools连接未建立',
                    'error_code': 'DEVTOOLS_NOT_CONNECTED'
                }
            
            # 记录DevTools连接信息
            logger.info(f"DevTools连接信息 - 实例ID: {self.devtools_manager.instance_id}, 连接ID: {self.devtools_manager.connection_id}", "_initialize_console")
            logger.info(f"DevTools WebSocket URL: {self.devtools_manager.ws_url}", "_initialize_console")
            
            # 2. 注册控制台消息事件回调
            logger.info("注册控制台消息事件回调", "_initialize_console")
            try:
                self.devtools_manager.register_event_callback("Console.messageAdded", self._on_console_message)
                logger.debug("控制台消息事件回调注册成功", "_initialize_console")
            except Exception as e:
                logger.error("注册控制台消息事件回调失败", "_initialize_console", e)
                logger.error(f"异常详情: {str(e)}", "_initialize_console")
                return {
                    'success': False,
                    'message': f'注册控制台消息事件回调失败: {str(e)}',
                    'error_code': 'CALLBACK_REGISTER_FAILED'
                }
            
            # 3. 启用控制台域
            logger.info("发送Console.enable命令", "_initialize_console")
            result = self.devtools_manager.send_command("Console.enable")
            
            if not result.get('success'):
                error_msg = result.get('message', 'Console.enable命令失败')
                logger.error(f"启用控制台域失败: {error_msg}", "_initialize_console")
                logger.error(f"错误详情: {result}", "_initialize_console")
                
                # 尝试第二次发送Console.enable命令
                logger.info("第一次Console.enable失败，尝试第二次发送", "_initialize_console")
                retry_result = self.devtools_manager.send_command("Console.enable")
                
                if not retry_result.get('success'):
                    retry_error = retry_result.get('message', '重试Console.enable命令失败')
                    logger.error(f"第二次尝试启用控制台域也失败: {retry_error}", "_initialize_console")
                    logger.error(f"第二次尝试错误详情: {retry_result}", "_initialize_console")
                    return {
                        'success': False,
                        'message': f'启用控制台域失败: {error_msg}，重试也失败: {retry_error}',
                        'error_code': 'CONSOLE_ENABLE_FAILED',
                        'first_attempt': result,
                        'retry_attempt': retry_result
                    }
                else:
                    logger.info("第二次尝试Console.enable命令成功", "_initialize_console")
                    result = retry_result
            else:
                logger.info("Console.enable命令成功", "_initialize_console")
                logger.debug(f"Console.enable响应: {result}", "_initialize_console")
            
            # 4. 获取现有的控制台消息
            logger.info("发送Console.messages命令获取现有消息", "_initialize_console")
            messages_result = self.devtools_manager.send_command("Console.messages")
            
            if messages_result.get('success'):
                # 处理现有消息
                messages = messages_result.get('result', {}).get('messages', [])
                logger.info(f"获取到 {len(messages)} 条现有控制台消息", "_initialize_console")
                logger.debug(f"现有消息详情: {messages[:3] if len(messages) > 0 else '无消息'}", "_initialize_console")
                
                for message in messages:
                    try:
                        self._on_console_message({'message': message})
                        logger.debug(f"处理现有消息: {message.get('text', '无文本')[:50]}", "_initialize_console")
                    except Exception as msg_e:
                        logger.warning(f"处理现有消息时发生异常: {str(msg_e)}", "_initialize_console")
            else:
                logger.warning("获取现有控制台消息失败，但继续初始化", "_initialize_console")
                logger.warning(f"获取消息失败详情: {messages_result}", "_initialize_console")
            
            # 5. 设置控制台连接状态
            self.connected = True
            logger.info("控制台连接状态已设置为已连接", "_initialize_console")
            
            # 6. 调用状态变更回调
            if self.on_status_change:
                try:
                    logger.debug("调用状态变更回调", "_initialize_console")
                    self.on_status_change(True, self.instance_id)
                    logger.debug("状态变更回调执行完成", "_initialize_console")
                except Exception as e:
                    logger.error("调用状态变更回调时发生异常", "_initialize_console", e)
                    logger.error(f"异常详情: {str(e)}", "_initialize_console")
            
            # 7. 添加系统消息到控制台
            self._add_system_message_to_buffer('info', '控制台连接初始化成功')
            logger.info(f"控制台连接初始化成功: {self.instance_id}", "_initialize_console")
            
            return {
                'success': True,
                'message': '控制台连接初始化成功'
            }
            
        except Exception as e:
            logger.error("初始化控制台连接时发生异常", "_initialize_console", e)
            logger.error(f"异常详情: {str(e)}", "_initialize_console")
            logger.error(f"异常堆栈: {traceback.format_exc()}", "_initialize_console")
            
            # 重置连接状态
            self.connected = False
            
            # 添加系统错误消息
            self._add_system_message_to_buffer('error', f'控制台初始化失败: {str(e)}')
            
            return {
                'success': False,
                'message': f'初始化控制台连接时发生异常: {str(e)}',
                'error_code': 'CONSOLE_INIT_ERROR',
                'exception': str(e),
                'exception_type': type(e).__name__
            }
    
    def _on_console_message(self, params: Dict[str, Any]) -> None:
        """
        处理Console.messageAdded事件
        
        Args:
            params: 事件参数
        """
        try:
            logger.debug(f"收到Console.messageAdded事件: {params}", "_on_console_message")
            
            # 提取消息
            message = params.get('message', {})
            
            # 转换为标准格式
            log_entry = {
                'type': 'console',
                'content': message.get('text', ''),
                'timestamp': int(message.get('timestamp', time.time() * 1000)),
                'level': message.get('level', 'log'),
                'url': message.get('url', ''),
                'line': message.get('line', 0),
                'column': message.get('column', 0)
            }
            
            # 处理参数
            if 'args' in message:
                args = []
                for arg in message.get('args', []):
                    args.append({
                        'type': arg.get('type', ''),
                        'value': arg.get('value', ''),
                        'description': arg.get('description', '')
                    })
                log_entry['args'] = args
            
            # 添加到缓冲区
            self.console_buffer.append(log_entry)
            
            # 限制缓冲区大小
            self._trim_buffer()
            
            # 调用输出回调
            if self.on_output:
                try:
                    # 批量发送消息，避免频繁更新导致前端卡顿
                    if len(self.console_buffer) > self.batch_size and not self.is_first_batch:
                        # 非首次批量发送，只发送最新的一条消息
                        self.on_output([log_entry])
                    else:
                        # 首次批量发送或消息量较少，发送全部消息
                        self.on_output([log_entry])
                        # 标记首次批量发送已完成
                        self.is_first_batch = False
                except Exception as e:
                    logger.error("调用输出回调时发生异常", "_on_console_message", e)
                
        except Exception as e:
            logger.error("处理Console.messageAdded事件时发生异常", "_on_console_message", e)
    
    def _on_devtools_message(self, message: Dict[str, Any]) -> None:
        """
        处理DevTools消息
        
        Args:
            message: DevTools消息
        """
        logger.debug(f"收到DevTools消息: {message}", "_on_devtools_message")
    
    def _on_devtools_status_change(self, connected: bool, instance_id: str) -> None:
        """
        处理DevTools状态变更
        
        Args:
            connected: 连接状态
            instance_id: 实例ID
        """
        logger.info(f"DevTools状态变更: connected={connected}, instance_id={instance_id}", "_on_devtools_status_change")
        
        # 更新连接状态
        self.connected = connected
                        
        # 调用状态变更回调
        if self.on_status_change:
            try:
                self.on_status_change(connected, instance_id)
            except Exception as e:
                logger.error("调用状态变更回调时发生异常", "_on_devtools_status_change", e)
    
    def _on_devtools_error(self, error: str) -> None:
        """
        处理DevTools错误
        
        Args:
            error: 错误信息
        """
        logger.error(f"DevTools错误: {error}", "_on_devtools_error")
        
        # 调用错误回调
        if self.on_error:
            try:
                self.on_error(error)
            except Exception as e:
                logger.error("调用错误回调时发生异常", "_on_devtools_error", e)
    
    def _add_to_command_history(self, command: str) -> None:
        """
        添加命令到历史记录
        
        Args:
            command: 命令
        """
        # 避免重复添加相同的最后一条命令
        if self.command_history and self.command_history[-1] == command:
            return
        
        # 添加到历史记录
        self.command_history.append(command)
        
        # 限制历史记录大小
        if len(self.command_history) > self.max_history_size:
            self.command_history = self.command_history[-self.max_history_size:]

    def _trim_buffer(self) -> None:
        """限制缓冲区大小，保留最新的消息"""
        if len(self.console_buffer) > self.max_buffer_size:
            # 记录被删除的消息数量
            removed_count = len(self.console_buffer) - self.max_buffer_size
            logger.debug(f"缓冲区超出限制，删除 {removed_count} 条旧消息", "_trim_buffer")
            
            # 保留最新的max_buffer_size条消息
            self.console_buffer = self.console_buffer[-self.max_buffer_size:]
            
            # 添加一条系统消息，告知用户旧消息已被删除
            if removed_count > 0:
                system_entry = {
                    'type': 'system',
                    'content': f"已自动清理 {removed_count} 条旧消息以优化性能",
                    'timestamp': int(time.time() * 1000),
                    'level': 'info'
                }
                self.console_buffer.append(system_entry)
                
                # 如果有输出回调，通知前端显示系统消息
                if self.on_output:
                    try:
                        self.on_output([system_entry])
                    except Exception as e:
                        logger.error("发送系统消息时发生异常", "_trim_buffer", e)
    
    def _check_instance_status(self) -> bool:
        """
        检查实例状态
        
        Returns:
            实例是否可用
        """
        try:
            # 获取实例列表
            result = self.client_api.list_instances()
            
            if result.get('success'):
                instances = result.get('instances', [])
                
                # 查找当前实例
                for instance in instances:
                    if instance.get('id') == self.instance_id:
                        # 检查实例状态
                        if instance.get('status') == 'ready':
                            return True
                        else:
                            logger.warning(f"实例状态异常: {instance.get('status')}", "_check_instance_status")
                            return False
                
                # 未找到实例
                logger.warning(f"未找到实例: {self.instance_id}", "_check_instance_status")
                return False
            else:
                logger.warning("获取实例列表失败", "_check_instance_status")
                return False
                
        except Exception as e:
            logger.error("检查实例状态时发生异常", "_check_instance_status", e)
            return False
    
    def _add_system_message_to_buffer(self, level: str, message: str) -> None:
        """添加系统消息到缓冲区并通知前端"""
        logger.debug(f"添加系统消息到缓冲区: [{level}] {message}", "_add_system_message_to_buffer")
        
        system_entry = {
            'type': 'system',
            'content': message,
            'timestamp': int(time.time() * 1000),
            'level': level
        }
        
        # 添加到缓冲区
        self.console_buffer.append(system_entry)
        logger.debug("已添加系统消息到缓冲区", "_add_system_message_to_buffer")
        
        # 保持缓冲区大小
        self._trim_buffer()
        logger.debug("缓冲区大小检查完成", "_add_system_message_to_buffer")
        
        # 调用输出回调
        if self.on_output:
            try:
                logger.debug("调用输出回调以广播系统消息", "_add_system_message_to_buffer")
                self.on_output([system_entry])
                logger.debug("输出回调执行完成", "_add_system_message_to_buffer")
            except Exception as e:
                logger.error("调用输出回调时发生异常", "_add_system_message_to_buffer", e)
        else:
            logger.debug("未设置输出回调，系统消息未广播", "_add_system_message_to_buffer") 