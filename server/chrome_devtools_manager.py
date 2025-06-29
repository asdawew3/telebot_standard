#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Chrome DevTools Protocol管理器
负责管理Chrome实例的远程调试功能，提供CDP连接和操作接口
"""

import os
import sys
import time
import json
import threading
import requests
import uuid
from typing import Dict, Any, List, Optional, Callable, Union
from urllib.parse import urlparse

from .logger import get_server_logger

# 获取日志实例
logger = get_server_logger()

class ChromeDevToolsManager:
    """Chrome DevTools Protocol管理器类"""
    
    _instance = None
    _lock = threading.RLock()
    
    @classmethod
    def get_instance(cls):
        """单例模式获取实例"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    logger.info("创建Chrome DevTools Protocol管理器实例", "ChromeDevToolsManager.get_instance")
                    cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        """初始化Chrome DevTools Protocol管理器"""
        logger.info("初始化Chrome DevTools Protocol管理器", "ChromeDevToolsManager.__init__")
        
        # 实例映射表 {instance_id: {debugging_url, ws_url, targets, ...}}
        self.instance_debuggers = {}
        
        # 连接映射表 {connection_id: {instance_id, ws_client, ...}}
        self.active_connections = {}
        
        # 线程安全锁
        self._instance_lock = threading.RLock()
        
        # 请求超时设置
        self.request_timeout = 10  # 秒
        
        logger.info("Chrome DevTools Protocol管理器初始化完成", "ChromeDevToolsManager.__init__")
    
    def enable_debugging_for_instance(self, instance_id: str, chrome_driver) -> Dict[str, Any]:
        """
        为Chrome实例启用远程调试功能
        
        Args:
            instance_id: 实例ID
            chrome_driver: WebDriver实例
            
        Returns:
            启用结果
        """
        logger.info(f"为实例启用远程调试功能: {instance_id}", "enable_debugging_for_instance")
        
        with self._instance_lock:
            try:
                # 检查实例是否已启用调试
                if instance_id in self.instance_debuggers:
                    logger.debug(f"实例已启用调试: {instance_id}", "enable_debugging_for_instance")
                    return {
                        'success': True,
                        'message': '远程调试已启用',
                        'debugging_info': self.instance_debuggers[instance_id]
                    }
                
                # 检查WebDriver是否可用
                if not chrome_driver:
                    logger.error(f"WebDriver不可用: {instance_id}", "enable_debugging_for_instance")
                    return {
                        'success': False,
                        'message': 'WebDriver不可用'
                    }
                
                # 获取Chrome调试地址
                debugging_url = None
                
                # 方法0: 优先从实例的debug_port属性获取调试端口
                try:
                    logger.debug("优先从实例属性获取调试端口", "enable_debugging_for_instance")
                    if hasattr(chrome_driver, 'debug_port'):
                        debug_port = getattr(chrome_driver, 'debug_port')
                        if debug_port:
                            debugging_url = f"localhost:{debug_port}"
                            logger.debug(f"从实例debug_port属性获取到调试地址: {debugging_url}", "enable_debugging_for_instance")
                except Exception as attr_e:
                    logger.warning(f"从实例debug_port属性获取调试端口失败: {attr_e}", "enable_debugging_for_instance")
                
                # 方法1: 尝试从WebDriver的service获取远程调试端口
                if not debugging_url:
                    try:
                        logger.debug("尝试从WebDriver的service获取调试端口", "enable_debugging_for_instance")
                        if hasattr(chrome_driver.service, 'service_url', None) and chrome_driver.service:
                            # 记录service信息用于调试
                            service_url = getattr(chrome_driver.service, 'service_url', None)
                            logger.debug(f"WebDriver service_url: {service_url}", "enable_debugging_for_instance")
                            
                            # 尝试从service中获取port
                            service_port = getattr(chrome_driver.service, 'port', None)
                            if service_port:
                                debug_port = service_port + 1  # 通常调试端口比service端口大1
                                debugging_url = f"localhost:{debug_port}"
                                logger.debug(f"从WebDriver service获取到调试地址: {debugging_url}", "enable_debugging_for_instance")
                    except Exception as svc_e:
                        logger.warning(f"从WebDriver service获取调试端口失败: {svc_e}", "enable_debugging_for_instance")
                
                # 方法2: 尝试从Chrome命令行参数中获取远程调试端口
                if not debugging_url:
                    try:
                        logger.debug("尝试从命令行参数获取调试端口", "enable_debugging_for_instance")
                        # 记录完整的capabilities用于调试
                        logger.debug(f"Chrome capabilities: {chrome_driver.capabilities}", "enable_debugging_for_instance")
                        
                        chrome_cmd = chrome_driver.capabilities.get('chrome', {}).get('chrome', {}).get('commandLine', '')
                        logger.debug(f"Chrome命令行: {chrome_cmd}", "enable_debugging_for_instance")
                        
                        # 查找远程调试端口参数
                        import re
                        port_match = re.search(r'--remote-debugging-port=(\d+)', chrome_cmd)
                        if port_match:
                            port = port_match.group(1)
                            debugging_url = f"localhost:{port}"
                            logger.debug(f"从命令行参数获取到调试地址: {debugging_url}", "enable_debugging_for_instance")
                    except Exception as cmd_e:
                        logger.warning(f"从命令行获取调试端口失败: {cmd_e}", "enable_debugging_for_instance")
                
                # 方法3: 尝试从执行脚本获取调试地址
                if not debugging_url:
                    try:
                        logger.debug("尝试从执行脚本获取调试地址", "enable_debugging_for_instance")
                        # 尝试不同的脚本方式
                        scripts_to_try = [
                            "return chrome.debuggerAddress",
                            "return window.chrome.debuggerAddress",
                            "return JSON.stringify(window.performance.timing)",
                            "return navigator.userAgent"
                        ]
                        
                        for script in scripts_to_try:
                            try:
                                result = chrome_driver.execute_script(script)
                                logger.debug(f"脚本执行结果: {result}", "enable_debugging_for_instance")
                                if result and isinstance(result, str) and ":" in result:
                                    debugging_url = result
                                    logger.debug(f"从脚本获取到调试地址: {debugging_url}", "enable_debugging_for_instance")
                                    break
                            except Exception as script_exec_e:
                                logger.debug(f"脚本 '{script}' 执行失败: {script_exec_e}", "enable_debugging_for_instance")
                                continue
                    except Exception as script_e:
                        logger.warning(f"从脚本获取调试地址失败: {script_e}", "enable_debugging_for_instance")
                
                # 如果所有方法都失败，尝试使用默认端口
                if not debugging_url:
                    logger.warning("所有方法获取调试地址都失败，尝试使用默认端口", "enable_debugging_for_instance")
                    
                    # 首先尝试9222-9299范围内的端口(与initialize_browser方法中使用的范围一致)
                    default_ports = list(range(9222, 9300))
                    # 随机打乱端口顺序，避免总是从同一个端口开始尝试
                    import random
                    random.shuffle(default_ports)
                    
                    logger.debug(f"尝试检查 {len(default_ports)} 个可能的调试端口", "enable_debugging_for_instance")
                    
                    for port in default_ports[:10]:  # 最多尝试10个端口
                        debugging_url = f"localhost:{port}"
                        logger.debug(f"尝试默认端口: {port}", "enable_debugging_for_instance")
                        
                        # 测试端口是否可用
                        try:
                            test_url = f"http://{debugging_url}/json/version"
                            response = requests.get(test_url, timeout=2)
                            if response.status_code == 200:
                                logger.info(f"默认端口可用: {port}", "enable_debugging_for_instance")
                                break
                            else:
                                debugging_url = None
                        except Exception as port_e:
                            logger.debug(f"端口 {port} 连接失败: {str(port_e)}", "enable_debugging_for_instance")
                            debugging_url = None
                            continue
                
                if not debugging_url:
                    logger.error(f"无法获取Chrome调试地址: {instance_id}", "enable_debugging_for_instance")
                    return {
                        'success': False,
                        'message': '无法获取Chrome调试地址'
                    }
                
                logger.debug(f"获取到Chrome调试地址: {debugging_url}", "enable_debugging_for_instance")
                
                # 解析调试地址
                parsed_url = urlparse(f"http://{debugging_url}")
                host = parsed_url.hostname or "localhost"
                port = parsed_url.port or 9222
                
                # 获取可用目标列表
                targets_url = f"http://{host}:{port}/json/list"
                logger.debug(f"请求Chrome调试目标列表: {targets_url}", "enable_debugging_for_instance")
                
                try:
                    # 增加重试逻辑
                    max_retries = 3
                    retry_count = 0
                    retry_delay = 1  # 初始延迟1秒
                    
                    while retry_count < max_retries:
                        try:
                            response = requests.get(targets_url, timeout=self.request_timeout)
                            response.raise_for_status()
                            targets = response.json()
                            
                            # 成功获取目标列表，跳出重试循环
                            break
                            
                        except (requests.exceptions.RequestException, json.JSONDecodeError) as retry_e:
                            retry_count += 1
                            if retry_count >= max_retries:
                                # 最后一次重试也失败，抛出异常
                                logger.error(f"获取调试目标列表失败，已重试{retry_count}次: {retry_e}", 
                                           "enable_debugging_for_instance")
                                raise
                            
                            # 记录重试信息
                            logger.warning(f"获取调试目标列表失败，将在{retry_delay}秒后重试(第{retry_count}次): {retry_e}", 
                                         "enable_debugging_for_instance")
                            
                            # 等待一段时间后重试，使用指数退避策略
                            time.sleep(retry_delay)
                            retry_delay *= 2  # 指数增长重试延迟
                    
                    if not targets or not isinstance(targets, list):
                        logger.error(f"无效的调试目标列表响应: {targets}", "enable_debugging_for_instance")
                        return {
                            'success': False,
                            'message': '无效的调试目标列表响应'
                        }
                    
                    logger.debug(f"获取到 {len(targets)} 个调试目标", "enable_debugging_for_instance")
                    
                    # 查找主页面目标
                    page_target = None
                    for target in targets:
                        if target.get('type') == 'page' and 'webSocketDebuggerUrl' in target:
                            page_target = target
                            break
                    
                    if not page_target:
                        logger.error("未找到可用的页面调试目标", "enable_debugging_for_instance")
                        return {
                            'success': False,
                            'message': '未找到可用的页面调试目标'
                        }
                    
                    # 保存调试信息
                    ws_url = page_target['webSocketDebuggerUrl']
                    logger.debug(f"获取到WebSocket调试URL: {ws_url}", "enable_debugging_for_instance")
                    
                    debugging_info = {
                        'debugging_url': debugging_url,
                        'host': host,
                        'port': port,
                        'ws_url': ws_url,
                        'target_id': page_target['id'],
                        'targets': targets,
                        'enabled_at': time.time(),
                        'connections': []
                    }
                    
                    self.instance_debuggers[instance_id] = debugging_info
                    
                    logger.info(f"实例远程调试功能启用成功: {instance_id}", "enable_debugging_for_instance")
                    return {
                        'success': True,
                        'message': '远程调试功能启用成功',
                        'debugging_info': debugging_info
                    }
                    
                except requests.exceptions.RequestException as e:
                    logger.error(f"请求调试目标列表失败: {e}", "enable_debugging_for_instance")
                    return {
                        'success': False,
                        'message': f'请求调试目标列表失败: {str(e)}'
                    }
                except json.JSONDecodeError as e:
                    logger.error(f"解析调试目标列表响应失败: {e}", "enable_debugging_for_instance")
                    return {
                        'success': False,
                        'message': f'解析调试目标列表响应失败: {str(e)}'
                    }
                    
            except Exception as e:
                logger.error("启用远程调试功能时发生异常", "enable_debugging_for_instance", e)
                return {
                    'success': False,
                    'message': f'启用远程调试功能时发生异常: {str(e)}'
                }
    
    def get_debugging_info(self, instance_id: str) -> Dict[str, Any]:
        """
        获取实例的调试信息
        
        Args:
            instance_id: 实例ID
            
        Returns:
            调试信息
        """
        logger.debug(f"获取实例调试信息: {instance_id}", "get_debugging_info")
        
        with self._instance_lock:
            if instance_id not in self.instance_debuggers:
                logger.warning(f"实例未启用调试功能: {instance_id}", "get_debugging_info")
                return {
                    'success': False,
                    'message': '实例未启用调试功能'
                }
            
            debugging_info = self.instance_debuggers[instance_id]
            
            # 更新目标列表
            try:
                host = debugging_info['host']
                port = debugging_info['port']
                targets_url = f"http://{host}:{port}/json/list"
                logger.debug(f"更新调试目标列表，URL: {targets_url}", "get_debugging_info")
                
                # 增加重试逻辑
                max_retries = 3
                retry_count = 0
                retry_delay = 1  # 初始延迟1秒
                
                while retry_count < max_retries:
                    try:
                        logger.debug(f"尝试获取调试目标列表 (尝试 {retry_count+1}/{max_retries})", "get_debugging_info")
                        response = requests.get(targets_url, timeout=self.request_timeout)
                        response.raise_for_status()
                        targets = response.json()
                        
                        if targets and isinstance(targets, list):
                            debugging_info['targets'] = targets
                            logger.debug(f"更新调试目标列表成功: {len(targets)} 个目标", "get_debugging_info")
                            # 成功获取目标列表，跳出重试循环
                            break
                        else:
                            logger.warning(f"调试目标列表无效: {targets}", "get_debugging_info")
                            retry_count += 1
                            
                    except (requests.exceptions.RequestException, json.JSONDecodeError) as retry_e:
                        retry_count += 1
                        if retry_count >= max_retries:
                            # 最后一次重试也失败，记录错误但不抛出异常
                            logger.error(f"更新调试目标列表失败，已重试{retry_count}次: {retry_e}", "get_debugging_info")
                            break
                        
                        # 记录重试信息
                        logger.warning(f"更新调试目标列表失败，将在{retry_delay}秒后重试(第{retry_count}次): {retry_e}", 
                                     "get_debugging_info")
                        
                        # 等待一段时间后重试，使用指数退避策略
                        time.sleep(retry_delay)
                        retry_delay *= 2  # 指数增长重试延迟
                
            except Exception as e:
                logger.warning(f"更新调试目标列表失败: {e}", "get_debugging_info")
                # 不影响返回结果，继续使用旧的目标列表
            
            return {
                'success': True,
                'message': '获取调试信息成功',
                'debugging_info': debugging_info
            }
    
    def create_connection(self, instance_id: str) -> Dict[str, Any]:
        """
        创建到Chrome实例的WebSocket连接
        
        Args:
            instance_id: 实例ID
            
        Returns:
            连接信息
        """
        logger.info(f"创建到Chrome实例的WebSocket连接: {instance_id}", "create_connection")
        
        with self._instance_lock:
            if instance_id not in self.instance_debuggers:
                logger.warning(f"实例未启用调试功能: {instance_id}", "create_connection")
                return {
                    'success': False,
                    'message': '实例未启用调试功能'
                }
            
            debugging_info = self.instance_debuggers[instance_id]
            ws_url = debugging_info['ws_url']
            
            # 创建连接ID
            connection_id = str(uuid.uuid4())
            
            # 创建连接信息
            connection_info = {
                'connection_id': connection_id,
                'instance_id': instance_id,
                'ws_url': ws_url,
                'created_at': time.time(),
                'last_activity': time.time(),
                'is_connected': False
            }
            
            # 保存连接信息
            self.active_connections[connection_id] = connection_info
            
            # 添加到实例的连接列表
            debugging_info['connections'].append(connection_id)
            
            logger.info(f"WebSocket连接信息创建成功: {connection_id}", "create_connection")
            return {
                'success': True,
                'message': 'WebSocket连接信息创建成功',
                'connection_id': connection_id,
                'connection_info': connection_info
            }
    
    def close_connection(self, connection_id: str) -> Dict[str, Any]:
        """
        关闭WebSocket连接
        
        Args:
            connection_id: 连接ID
            
        Returns:
            关闭结果
        """
        logger.info(f"关闭WebSocket连接: {connection_id}", "close_connection")
        
        with self._instance_lock:
            if connection_id not in self.active_connections:
                logger.warning(f"连接不存在: {connection_id}", "close_connection")
                return {
                    'success': False,
                    'message': '连接不存在'
                }
            
            connection_info = self.active_connections[connection_id]
            instance_id = connection_info['instance_id']
            
            # 从实例的连接列表中移除
            if instance_id in self.instance_debuggers:
                connections = self.instance_debuggers[instance_id]['connections']
                if connection_id in connections:
                    connections.remove(connection_id)
                    logger.debug(f"从实例连接列表中移除连接: {connection_id}", "close_connection")
            
            # 从活动连接中移除
            del self.active_connections[connection_id]
            logger.debug(f"从活动连接中移除: {connection_id}", "close_connection")
            
            logger.info(f"WebSocket连接关闭成功: {connection_id}", "close_connection")
            return {
                'success': True,
                'message': 'WebSocket连接关闭成功'
            }
    
    def disable_debugging_for_instance(self, instance_id: str) -> Dict[str, Any]:
        """
        为Chrome实例禁用远程调试功能
        
        Args:
            instance_id: 实例ID
            
        Returns:
            禁用结果
        """
        logger.info(f"为实例禁用远程调试功能: {instance_id}", "disable_debugging_for_instance")
        
        with self._instance_lock:
            if instance_id not in self.instance_debuggers:
                logger.warning(f"实例未启用调试功能: {instance_id}", "disable_debugging_for_instance")
                return {
                    'success': False,
                    'message': '实例未启用调试功能'
                }
            
            debugging_info = self.instance_debuggers[instance_id]
            
            # 关闭所有连接
            for connection_id in debugging_info['connections'][:]:  # 使用副本避免迭代时修改
                self.close_connection(connection_id)
            
            # 从实例映射表中移除
            del self.instance_debuggers[instance_id]
            logger.debug(f"从实例映射表中移除: {instance_id}", "disable_debugging_for_instance")
            
            logger.info(f"实例远程调试功能禁用成功: {instance_id}", "disable_debugging_for_instance")
            return {
                'success': True,
                'message': '远程调试功能禁用成功'
            }
    
    def cleanup(self) -> None:
        """清理所有连接和调试信息"""
        logger.info("清理所有连接和调试信息", "cleanup")
        
        with self._instance_lock:
            # 关闭所有连接
            for connection_id in list(self.active_connections.keys()):
                self.close_connection(connection_id)
            
            # 清空实例映射表
            self.instance_debuggers.clear()
            
            logger.info("所有连接和调试信息已清理", "cleanup")

# 全局获取函数
def get_chrome_devtools_manager():
    """获取Chrome DevTools Protocol管理器实例"""
    return ChromeDevToolsManager.get_instance()