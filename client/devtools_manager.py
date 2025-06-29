#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DevTools管理器模块
负责与Chrome DevTools Protocol交互，实现浏览器调试功能
"""

import os
import sys
import time
import json
import threading
import websocket
import uuid
import socket
import traceback
from typing import Dict, Any, List, Optional, Callable, Union

from .client_logger import get_client_logger, log_debug, log_info, log_error, log_warning, log_operation
from .client_api import ClientAPI

# 获取日志实例
logger = get_client_logger()

class DevToolsManager:
    """DevTools管理器类"""
    
    def __init__(self, client_api: ClientAPI):
        """
        初始化DevTools管理器
        
        Args:
            client_api: 客户端API实例
        """
        logger.info("初始化DevTools管理器", "DevToolsManager.__init__")
        
        # 保存API客户端
        self.client_api = client_api
        
        # 连接状态
        self.connected = False
        self.instance_id = None
        self.connection_id = None
        self.ws_url = None
        
        # WebSocket连接
        self.ws = None
        self.ws_lock = threading.RLock()
        
        # 消息ID计数器
        self.message_id = 0
        self.message_id_lock = threading.Lock()
        
        # 消息回调
        self.message_callbacks = {}
        self.event_callbacks = {}
        
        # 线程安全
        self.command_lock = threading.Lock()
        
        # 轮询控制
        self.ws_thread = None
        self.stop_ws = threading.Event()
        
        # 回调函数
        self.on_message = None  # 消息回调
        self.on_error = None    # 错误回调
        self.on_status_change = None  # 状态变更回调
        
        logger.debug("DevTools管理器初始化完成", "DevToolsManager.__init__")
    
    def connect(self, instance_id: str) -> Dict[str, Any]:
        """
        连接到实例的DevTools
        
        Args:
            instance_id: 实例ID
            
        Returns:
            连接结果
        """
        logger.info(f"开始连接到实例DevTools: {instance_id}", "connect")
        
        # 检查是否已连接
        if self.connected and self.instance_id == instance_id:
            logger.debug("已连接到该实例DevTools，无需重复连接", "connect")
            return {
                'success': True,
                'message': '已连接到该实例DevTools',
                'instance_id': instance_id
            }
        
        # 如果已连接到其他实例，先断开
        if self.connected and self.instance_id != instance_id:
            logger.debug(f"已连接到其他实例 {self.instance_id}，先断开", "connect")
            disconnect_result = self.disconnect()
            logger.debug(f"断开连接结果: {disconnect_result}", "connect")
        
        try:
            # 启用DevTools
            logger.debug(f"启用实例DevTools: {instance_id}", "connect")
            enable_result = self.client_api.enable_devtools(instance_id)
            
            if not enable_result.get('success'):
                error_msg = enable_result.get('message', '启用DevTools失败')
                logger.error(f"启用DevTools失败: {error_msg}", "connect")
                return enable_result
            
            # 创建DevTools连接
            logger.debug(f"创建DevTools连接: {instance_id}", "connect")
            connect_result = self.client_api.create_devtools_connection(instance_id)
            
            if not connect_result.get('success'):
                error_msg = connect_result.get('message', '创建DevTools连接失败')
                logger.error(f"创建DevTools连接失败: {error_msg}", "connect")
                return connect_result
            
            # 获取连接信息
            connection_info = connect_result.get('connection_info', {})
            self.connection_id = connection_info.get('connection_id')
            self.ws_url = connection_info.get('ws_url')
            
            if not self.connection_id or not self.ws_url:
                logger.error(f"连接信息不完整: connection_id={self.connection_id}, ws_url={self.ws_url}", "connect")
                return {
                    'success': False,
                    'message': 'DevTools连接信息不完整',
                    'error_code': 'INCOMPLETE_CONNECTION_INFO'
                }
            
            # 设置实例ID
            self.instance_id = instance_id
            
            # 连接WebSocket
            ws_connect_result = self._connect_websocket()
            
            if not ws_connect_result.get('success'):
                error_msg = ws_connect_result.get('message', 'WebSocket连接失败')
                logger.error(f"WebSocket连接失败: {error_msg}", "connect")
                return ws_connect_result
            
            # 更新连接状态
            self.connected = True
            
            # 调用状态变更回调
            if self.on_status_change:
                try:
                    logger.debug("调用状态变更回调", "connect")
                    self.on_status_change(True, instance_id)
                except Exception as e:
                    logger.error("调用状态变更回调时发生异常", "connect", e)
            
            logger.info(f"成功连接到实例DevTools: {instance_id}", "connect")
            log_operation("连接到实例DevTools", "connect", {
                'instance_id': instance_id,
                'connection_id': self.connection_id
            })
            
            return {
                'success': True,
                'message': '成功连接到实例DevTools',
                'instance_id': instance_id,
                'connection_id': self.connection_id
            }
            
        except Exception as e:
            logger.error("连接到实例DevTools时发生异常", "connect", e)
            
            # 重置状态
            self.instance_id = None
            self.connection_id = None
            self.ws_url = None
            self.connected = False
            
            # 确保WebSocket已关闭
            self._close_websocket()
            
            return {
                'success': False,
                'message': f'连接到实例DevTools时发生异常: {str(e)}'
            }
    
    def disconnect(self) -> Dict[str, Any]:
        """
        断开DevTools连接
        
        Returns:
            断开结果
        """
        logger.info("断开DevTools连接", "disconnect")
        
        # 保存当前连接信息
        prev_instance_id = self.instance_id
        prev_connection_id = self.connection_id
        
        try:
            # 关闭WebSocket
            self._close_websocket()
            
            # 重置状态
            self.connected = False
            self.instance_id = None
            self.connection_id = None
            self.ws_url = None
            
            # 调用状态变更回调
            if self.on_status_change:
                try:
                    self.on_status_change(False, prev_instance_id)
                except Exception as e:
                    logger.error("调用状态变更回调时发生异常", "disconnect", e)
            
            logger.info("DevTools已断开连接", "disconnect")
            log_operation("DevTools断开连接", "disconnect", {
                'instance_id': prev_instance_id,
                'connection_id': prev_connection_id
            })
            
            return {
                'success': True,
                'message': 'DevTools已断开连接'
            }
            
        except Exception as e:
            logger.error("断开DevTools连接时发生异常", "disconnect", e)
            
            # 强制重置状态
            self.connected = False
            self.instance_id = None
            self.connection_id = None
            self.ws_url = None
            
            return {
                'success': False,
                'message': f'断开DevTools连接时发生异常: {str(e)}'
            }
    
    def send_command(self, method: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """
        发送DevTools命令
        
        Args:
            method: 命令方法名
            params: 命令参数
            
        Returns:
            命令执行结果
        """
        logger.debug(f"发送DevTools命令: {method}", "send_command")
        logger.debug(f"命令参数: {params}", "send_command")
        
        if not self.connected or not self.ws:
            logger.error("DevTools未连接，无法发送命令", "send_command")
            logger.error(f"连接状态: connected={self.connected}, ws={self.ws is not None}", "send_command")
            logger.error(f"实例ID: {self.instance_id}", "send_command")
            return {
                'success': False,
                'message': 'DevTools未连接',
                'error_code': 'NOT_CONNECTED',
                'connection_status': {
                    'connected': self.connected,
                    'has_ws': self.ws is not None,
                    'instance_id': self.instance_id
                }
            }
        
        # 重试参数
        max_retries = 2  # 最多重试2次
        retry_delay = 1  # 重试间隔1秒
        
        for retry_count in range(max_retries + 1):  # +1是因为包括首次尝试
            try:
                # 记录重试信息
                if retry_count > 0:
                    logger.info(f"第 {retry_count} 次重试发送命令: {method}", "send_command")
                
                # 生成消息ID
                with self.message_id_lock:
                    self.message_id += 1
                    message_id = self.message_id
                
                # 构建命令
                command = {
                    'id': message_id,
                    'method': method
                }
                
                if params:
                    command['params'] = params
                
                # 创建结果事件
                result_event = threading.Event()
                result_data = {'result': None, 'error': None}
                
                # 注册回调
                def callback(response):
                    if 'result' in response:
                        result_data['result'] = response['result']
                    if 'error' in response:
                        result_data['error'] = response['error']
                    result_event.set()
                
                # 添加到回调字典
                with self.ws_lock:
                    self.message_callbacks[message_id] = callback
                
                # 发送命令
                command_json = json.dumps(command)
                logger.debug(f"发送WebSocket消息: {command_json}", "send_command")
                
                with self.ws_lock:
                    if self.ws:
                        self.ws.send(command_json)
                    else:
                        logger.error("WebSocket连接已关闭，无法发送命令", "send_command")
                        return {
                            'success': False,
                            'message': 'WebSocket连接已关闭',
                            'error_code': 'WS_CLOSED'
                        }
                
                # 等待结果
                timeout = 15  # 降低超时时间为15秒
                start_time = time.time()
                logger.debug(f"等待命令响应，超时时间: {timeout}秒", "send_command")
                
                if not result_event.wait(timeout):
                    elapsed = time.time() - start_time
                    logger.warning(f"DevTools命令超时: {method} (尝试 {retry_count+1}/{max_retries+1}), 已等待 {elapsed:.2f}秒", "send_command")
                    logger.warning(f"命令ID: {message_id}, 参数: {params}", "send_command")
                    logger.warning(f"实例ID: {self.instance_id}, 连接ID: {self.connection_id}", "send_command")
                    
                    # 检查WebSocket状态
                    ws_status = "已关闭" if not self.ws else "已连接"
                    logger.warning(f"WebSocket状态: {ws_status}", "send_command")
                    
                    # 移除回调
                    with self.ws_lock:
                        self.message_callbacks.pop(message_id, None)
                    
                    # 如果还有重试次数，则继续重试
                    if retry_count < max_retries:
                        logger.info(f"将在 {retry_delay} 秒后重试命令: {method}", "send_command")
                        time.sleep(retry_delay)
                        continue
                    
                    # 所有重试都失败
                    logger.error(f"命令 {method} 在 {max_retries + 1} 次尝试后仍然超时", "send_command")
                    return {
                        'success': False,
                        'message': f'DevTools命令超时: {method}',
                        'error_code': 'COMMAND_TIMEOUT',
                        'retries': retry_count,
                        'elapsed': elapsed,
                        'command_id': message_id,
                        'ws_status': ws_status,
                        'connection_id': self.connection_id
                    }
                
                # 处理结果
                elapsed = time.time() - start_time
                logger.debug(f"命令响应时间: {elapsed:.2f}秒", "send_command")
                
                if result_data['error']:
                    error_msg = result_data['error']
                    logger.warning(f"DevTools命令执行失败: {method}, 错误: {error_msg}", "send_command")
                    logger.warning(f"命令ID: {message_id}, 参数: {params}", "send_command")
                    
                    # 如果还有重试次数，则继续重试
                    if retry_count < max_retries:
                        logger.info(f"将在 {retry_delay} 秒后重试命令: {method}", "send_command")
                        time.sleep(retry_delay)
                        continue
                    
                    logger.error(f"命令 {method} 在 {max_retries + 1} 次尝试后仍然失败", "send_command")
                    return {
                        'success': False,
                        'message': f"DevTools命令执行失败: {error_msg}",
                        'error_code': 'COMMAND_ERROR',
                        'error_data': error_msg,
                        'retries': retry_count,
                        'elapsed': elapsed,
                        'command_id': message_id
                    }
                
                logger.debug(f"DevTools命令执行成功: {method}", "send_command")
                logger.debug(f"响应结果: {result_data['result']}", "send_command")
                
                return {
                    'success': True,
                    'result': result_data['result'],
                    'retries': retry_count,
                    'elapsed': elapsed,
                    'command_id': message_id
                }
                
            except Exception as e:
                logger.error(f"发送DevTools命令时发生异常: {method}", "send_command", e)
                logger.error(f"异常详情: {str(e)}", "send_command")
                logger.error(f"异常堆栈: {traceback.format_exc()}", "send_command")
                
                # 如果还有重试次数，则继续重试
                if retry_count < max_retries:
                    logger.info(f"将在 {retry_delay} 秒后重试命令: {method}", "send_command")
                    time.sleep(retry_delay)
                    continue
                
                # 所有重试都失败
                logger.error(f"命令 {method} 在 {max_retries + 1} 次尝试后仍然异常", "send_command")
                return {
                    'success': False,
                    'message': f'发送DevTools命令时发生异常: {str(e)}',
                    'error_code': 'COMMAND_EXCEPTION',
                    'exception': str(e),
                    'exception_type': type(e).__name__,
                    'retries': retry_count
                }
    
    def register_event_callback(self, event: str, callback: Callable) -> None:
        """
        注册事件回调
        
        Args:
            event: 事件名称
            callback: 回调函数
        """
        logger.debug(f"注册事件回调: {event}", "register_event_callback")
        
        with self.ws_lock:
            if event not in self.event_callbacks:
                self.event_callbacks[event] = []
            self.event_callbacks[event].append(callback)
    
    def unregister_event_callback(self, event: str, callback: Callable) -> None:
        """
        取消注册事件回调
        
        Args:
            event: 事件名称
            callback: 回调函数
        """
        logger.debug(f"取消注册事件回调: {event}", "unregister_event_callback")
        
        with self.ws_lock:
            if event in self.event_callbacks and callback in self.event_callbacks[event]:
                self.event_callbacks[event].remove(callback)
    
    def set_callbacks(self, on_message: Optional[Callable] = None,
                     on_status_change: Optional[Callable] = None,
                     on_error: Optional[Callable] = None) -> None:
        """
        设置回调函数
        
        Args:
            on_message: 消息回调
            on_status_change: 状态变更回调
            on_error: 错误回调
        """
        logger.debug("设置DevTools回调函数", "set_callbacks")
        
        self.on_message = on_message
        self.on_status_change = on_status_change
        self.on_error = on_error
    
    def _connect_websocket(self) -> Dict[str, Any]:
        """
        连接WebSocket
        
        Returns:
            连接结果
        """
        logger.info(f"开始连接WebSocket: {self.ws_url}", "_connect_websocket")
        
        # 关闭已有连接
        self._close_websocket()
        
        # 重试参数
        max_retries = 3
        retry_delay = 2  # 秒
        
        for retry_count in range(max_retries):
            try:
                # 验证WebSocket URL
                if not self.ws_url or not self.ws_url.startswith("ws://"):
                    logger.error(f"无效的WebSocket URL: {self.ws_url}", "_connect_websocket")
                    return {
                        'success': False,
                        'message': f'无效的WebSocket URL: {self.ws_url}',
                        'error_code': 'INVALID_WS_URL'
                    }
                
                # 创建WebSocket连接
                logger.debug(f"创建WebSocket连接 (尝试 {retry_count+1}/{max_retries}): {self.ws_url}", "_connect_websocket")
                
                # 设置超时和重试
                websocket.setdefaulttimeout(30)  # 30秒超时
                
                # 准备连接参数
                ws_options = {
                    'enable_multithread': True,
                    'skip_utf8_validation': False,
                    'ping_interval': 10,  # 10秒发送一次ping
                    'ping_timeout': 5,    # 5秒未收到pong则认为连接断开
                }
                
                logger.debug(f"WebSocket连接参数: {ws_options}", "_connect_websocket")
                
                # 创建WebSocket连接
                self.ws = websocket.WebSocketApp(
                    self.ws_url,
                    on_open=self._on_ws_open,
                    on_message=self._on_ws_message,
                    on_error=self._on_ws_error,
                    on_close=self._on_ws_close,
                    header=[
                        "Origin: http://localhost",  # 设置Origin头，解决403 Forbidden问题
                        "User-Agent: Chrome DevTools Client/1.0"  # 添加User-Agent
                    ]
                )
                
                # 启动WebSocket线程
                self.stop_ws.clear()
                self.ws_thread = threading.Thread(target=self._ws_run_forever)
                self.ws_thread.daemon = True
                self.ws_thread.start()
                
                # 等待连接建立
                logger.debug("等待WebSocket连接建立", "_connect_websocket")
                wait_time = 0
                max_wait = 15  # 最多等待15秒
                check_interval = 0.5  # 每0.5秒检查一次
                
                while not self.connected and wait_time < max_wait:
                    time.sleep(check_interval)
                    wait_time += check_interval
                    
                    # 检查线程是否仍在运行
                    if not self.ws_thread.is_alive():
                        logger.error("WebSocket线程已终止", "_connect_websocket")
                        break
                    
                    # 每2秒输出一次等待日志
                    if int(wait_time) % 2 == 0 and wait_time > 0:
                        logger.debug(f"已等待 {wait_time:.1f} 秒，连接状态: {self.connected}", "_connect_websocket")
                
                # 检查连接是否建立
                if self.connected:
                    logger.info(f"WebSocket连接成功: {self.ws_url}", "_connect_websocket")
                    return {
                        'success': True,
                        'message': 'WebSocket连接成功',
                        'wait_time': wait_time
                    }
                
                # 如果连接失败，但还有重试次数，则继续重试
                if retry_count < max_retries - 1:
                    logger.warning(f"WebSocket连接失败，将在 {retry_delay} 秒后重试 ({retry_count+1}/{max_retries})", "_connect_websocket")
                    self._close_websocket()  # 确保关闭失败的连接
                    time.sleep(retry_delay)  # 等待重试延迟
                    continue
                
                # 所有重试都失败
                logger.error(f"WebSocket连接超时，已尝试 {max_retries} 次: {self.ws_url}", "_connect_websocket")
                self._close_websocket()
                return {
                    'success': False,
                    'message': f'WebSocket连接超时，已尝试 {max_retries} 次',
                    'error_code': 'WS_CONNECTION_TIMEOUT',
                    'wait_time': wait_time
                }
                
            except Exception as e:
                logger.error("WebSocket连接失败", "_connect_websocket", e)
                
                # 详细记录错误信息
                error_type = type(e).__name__
                error_msg = str(e)
                
                logger.error(f"WebSocket连接异常: {error_type}: {error_msg}", "_connect_websocket")
                logger.error(f"WebSocket URL: {self.ws_url}", "_connect_websocket")
                
                # 清理资源
                self._close_websocket()
                
                # 如果还有重试次数，则继续重试
                if retry_count < max_retries - 1:
                    logger.warning(f"将在 {retry_delay} 秒后重试 ({retry_count+1}/{max_retries})", "_connect_websocket")
                    time.sleep(retry_delay)
                    continue
                
                # 所有重试都失败
                return {
                    'success': False,
                    'message': f'WebSocket连接失败 ({max_retries} 次尝试): {error_type}: {error_msg}',
                    'error_code': 'WS_CONNECTION_ERROR',
                    'error_details': {
                        'type': error_type,
                        'message': error_msg,
                        'ws_url': self.ws_url,
                        'retries': max_retries
                    }
                }
    
    def _close_websocket(self) -> None:
        """关闭WebSocket连接"""
        logger.debug("关闭WebSocket连接", "_close_websocket")
        
        # 检查是否有活跃的WebSocket连接
        if not self.ws:
            logger.debug("WebSocket连接不存在，无需关闭", "_close_websocket")
            return
        
        # 停止WebSocket线程
        logger.debug("设置WebSocket线程停止标志", "_close_websocket")
        self.stop_ws.set()
        
        # 关闭WebSocket连接
        try:
            logger.debug("开始关闭WebSocket连接", "_close_websocket")
            self.ws.close()
            logger.debug("WebSocket连接关闭命令已发送", "_close_websocket")
        except Exception as e:
            logger.warning(f"关闭WebSocket时发生异常: {e}", "_close_websocket")
            logger.debug(f"异常类型: {type(e).__name__}, 异常详情: {str(e)}", "_close_websocket")
        
        # 等待线程结束
        if self.ws_thread and self.ws_thread.is_alive():
            logger.debug("等待WebSocket线程结束", "_close_websocket")
            try:
                self.ws_thread.join(timeout=2)  # 增加超时时间到2秒
                if self.ws_thread.is_alive():
                    logger.warning("WebSocket线程在超时时间内未结束", "_close_websocket")
                else:
                    logger.debug("WebSocket线程已正常结束", "_close_websocket")
            except Exception as e:
                logger.warning(f"等待WebSocket线程结束时发生异常: {e}", "_close_websocket")
        else:
            logger.debug("WebSocket线程不存在或已结束", "_close_websocket")
        
        # 清理资源
        logger.debug("清理WebSocket相关资源", "_close_websocket")
        self.ws = None
        self.ws_thread = None
        
        logger.debug("WebSocket连接关闭和资源清理完成", "_close_websocket")
    
    def _ws_run_forever(self) -> None:
        """WebSocket线程函数"""
        logger.debug("启动WebSocket线程", "_ws_run_forever")
        
        try:
            # 设置WebSocket运行参数
            run_options = {
                'ping_interval': 10,  # 10秒发送一次ping
                'ping_timeout': 5,    # 5秒未收到pong则认为连接断开
                'skip_utf8_validation': False,
                'sockopt': [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]  # 禁用Nagle算法，减少延迟
            }
            
            logger.debug(f"WebSocket运行参数: {run_options}", "_ws_run_forever")
            self.ws.run_forever(**run_options)
        except Exception as e:
            logger.error("WebSocket线程异常", "_ws_run_forever", e)
        
        logger.debug("WebSocket线程结束", "_ws_run_forever")
    
    def _on_ws_message(self, ws, message: str) -> None:
        """
        WebSocket消息回调
        
        Args:
            ws: WebSocket实例
            message: 消息内容
        """
        try:
            # 解析消息
            data = json.loads(message)
            
            # 处理回调
            if 'id' in data:
                message_id = data['id']
                with self.ws_lock:
                    callback = self.message_callbacks.pop(message_id, None)
                
                if callback:
                    try:
                        callback(data)
                    except Exception as e:
                        logger.error(f"执行消息回调时发生异常: {e}", "_on_ws_message")
            
            # 处理事件
            if 'method' in data:
                event = data['method']
                params = data.get('params', {})
                
                # 调用事件回调
                with self.ws_lock:
                    callbacks = self.event_callbacks.get(event, [])[:]
                
                for callback in callbacks:
                    try:
                        callback(params)
                    except Exception as e:
                        logger.error(f"执行事件回调时发生异常: {e}", "_on_ws_message")
            
            # 调用全局消息回调
            if self.on_message:
                try:
                    self.on_message(data)
                except Exception as e:
                    logger.error(f"执行全局消息回调时发生异常: {e}", "_on_ws_message")
                
        except Exception as e:
            logger.error("处理WebSocket消息时发生异常", "_on_ws_message", e)
            
            # 调用错误回调
            if self.on_error:
                try:
                    self.on_error(f"处理WebSocket消息时发生异常: {str(e)}")
                except Exception as e:
                    logger.error(f"执行错误回调时发生异常: {e}", "_on_ws_message")
    
    def _on_ws_error(self, ws, error) -> None:
        """
        WebSocket错误回调
        
        Args:
            ws: WebSocket实例
            error: 错误信息
        """
        logger.error(f"WebSocket错误: {error}", "_on_ws_error")
        
        # 调用错误回调
        if self.on_error:
            try:
                self.on_error(f"WebSocket错误: {str(error)}")
            except Exception as e:
                logger.error(f"执行错误回调时发生异常: {e}", "_on_ws_error")
    
    def _on_ws_close(self, ws, close_status_code, close_msg) -> None:
        """
        WebSocket关闭回调
        
        Args:
            ws: WebSocket实例
            close_status_code: 关闭状态码
            close_msg: 关闭消息
        """
        logger.info(f"WebSocket连接关闭: {close_status_code} {close_msg}", "_on_ws_close")
        
        # 如果不是主动关闭，则尝试重新连接
        if not self.stop_ws.is_set() and self.connected:
            logger.warning("WebSocket连接意外关闭，尝试重新连接", "_on_ws_close")
            
            # 调用错误回调
            if self.on_error:
                try:
                    self.on_error("WebSocket连接意外关闭")
                except Exception as e:
                    logger.error(f"执行错误回调时发生异常: {e}", "_on_ws_close")
            
            # 尝试重新连接
            try:
                self._connect_websocket()
            except Exception as e:
                logger.error("重新连接WebSocket失败", "_on_ws_close", e)
                
                # 更新连接状态
                self.connected = False
                
                # 调用状态变更回调
                if self.on_status_change:
                    try:
                        self.on_status_change(False, self.instance_id)
                    except Exception as e:
                        logger.error(f"执行状态变更回调时发生异常: {e}", "_on_ws_close")
    
    def _on_ws_open(self, ws) -> None:
        """
        WebSocket连接打开回调
        
        Args:
            ws: WebSocket实例
        """
        logger.info("WebSocket连接已打开", "_on_ws_open")
        logger.info(f"WebSocket URL: {self.ws_url}", "_on_ws_open")
        logger.info(f"实例ID: {self.instance_id}", "_on_ws_open")
        logger.info(f"连接ID: {self.connection_id}", "_on_ws_open")
        
        try:
            # 设置连接状态
            self.connected = True
            logger.debug("WebSocket连接状态已设置为已连接", "_on_ws_open")
            
            # 创建一个异步线程来发送初始化命令，避免阻塞WebSocket主线程
            def send_init_commands():
                try:
                    # 添加短暂延迟，确保WebSocket连接完全稳定
                    time.sleep(0.5)
                    logger.debug("开始发送初始化命令序列", "send_init_commands")
                    
                    # 发送一个Runtime.enable命令以启用运行时事件
                    logger.info("发送Runtime.enable命令", "send_init_commands")
                    runtime_result = self.send_command("Runtime.enable")
                    if not runtime_result.get('success'):
                        logger.error(f"Runtime.enable命令失败: {runtime_result.get('message')}", "send_init_commands")
                        logger.error(f"错误详情: {runtime_result}", "send_init_commands")
                    else:
                        logger.info("Runtime.enable命令成功", "send_init_commands")
                        logger.debug(f"Runtime.enable响应: {runtime_result}", "send_init_commands")
                    
                    # 添加短暂延迟，避免命令发送过快
                    time.sleep(0.5)
                    
                    # 发送Console.enable命令以启用控制台事件
                    logger.info("发送Console.enable命令", "send_init_commands")
                    console_result = self.send_command("Console.enable")
                    if not console_result.get('success'):
                        logger.error(f"Console.enable命令失败: {console_result.get('message')}", "send_init_commands")
                        logger.error(f"错误详情: {console_result}", "send_init_commands")
                    else:
                        logger.info("Console.enable命令成功", "send_init_commands")
                        logger.debug(f"Console.enable响应: {console_result}", "send_init_commands")
                    
                    # 发送额外的命令以确保控制台完全初始化
                    logger.info("发送Page.enable命令以确保页面事件可用", "send_init_commands")
                    page_result = self.send_command("Page.enable")
                    if not page_result.get('success'):
                        logger.warning(f"Page.enable命令失败: {page_result.get('message')}", "send_init_commands")
                    else:
                        logger.info("Page.enable命令成功", "send_init_commands")
                    
                    # 发送Network.enable命令以启用网络事件
                    logger.info("发送Network.enable命令", "send_init_commands")
                    network_result = self.send_command("Network.enable")
                    if not network_result.get('success'):
                        logger.warning(f"Network.enable命令失败: {network_result.get('message')}", "send_init_commands")
                    else:
                        logger.info("Network.enable命令成功", "send_init_commands")
                    
                    logger.info("所有初始化命令发送完成", "send_init_commands")
                except Exception as e:
                    logger.error("发送初始化命令时发生异常", "send_init_commands", e)
                    logger.error(f"异常详情: {str(e)}", "send_init_commands")
                    logger.error(f"异常堆栈: {traceback.format_exc()}", "send_init_commands")
                    
                    # 调用错误回调
                    if self.on_error:
                        try:
                            self.on_error(f"初始化DevTools命令失败: {str(e)}")
                        except Exception as callback_e:
                            logger.error(f"调用错误回调时发生异常: {callback_e}", "send_init_commands")
            
            # 启动异步线程发送初始化命令
            logger.debug("创建并启动初始化命令线程", "_on_ws_open")
            init_thread = threading.Thread(target=send_init_commands)
            init_thread.daemon = True
            init_thread.start()
            logger.debug("初始化命令线程已启动", "_on_ws_open")
            
            # 记录连接成功
            logger.info(f"WebSocket连接成功并开始初始化: {self.ws_url}", "_on_ws_open")
            log_operation("WebSocket连接成功", "_on_ws_open", {
                'instance_id': self.instance_id,
                'connection_id': self.connection_id,
                'ws_url': self.ws_url
            })
            
            # 调用状态变更回调
            if self.on_status_change:
                try:
                    logger.debug("调用状态变更回调", "_on_ws_open")
                    self.on_status_change(True, self.instance_id)
                    logger.debug("状态变更回调执行完成", "_on_ws_open")
                except Exception as e:
                    logger.error("调用状态变更回调时发生异常", "_on_ws_open", e)
                    logger.error(f"异常详情: {str(e)}", "_on_ws_open")
        
        except Exception as e:
            logger.error("WebSocket打开回调处理异常", "_on_ws_open", e)
            logger.error(f"异常详情: {str(e)}", "_on_ws_open")
            logger.error(f"异常堆栈: {traceback.format_exc()}", "_on_ws_open")
            # 不设置连接状态为False，让外部重试机制处理
    
    def __del__(self):
        """析构函数，确保资源清理"""
        try:
            self._close_websocket()
        except Exception:
            pass
