#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
客户端API通信模块
负责与服务端进行API交互，处理认证、实例管理等功能
"""

import os
import sys
import time
import json
import requests
from typing import Dict, Any, List, Optional, Union

from .client_logger import get_client_logger, log_debug, log_info, log_error, log_warning, log_operation

# 获取日志实例
logger = get_client_logger()

class ClientAPI:
    """客户端API通信类"""
    
    def __init__(self, server_url: str = 'http://127.0.0.1:5000'):
        """
        初始化API通信
        
        Args:
            server_url: 服务器地址
        """
        logger.info(f"初始化客户端API通信模块", "ClientAPI.__init__")
        logger.debug(f"服务器地址: {server_url}", "ClientAPI.__init__")
        
        # 设置服务器地址
        self.server_url = server_url.rstrip('/')
        
        # 会话管理
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'TelegramBotClient/2.0'
        })
        
        # 认证状态
        self.is_authenticated = False
        self.current_user = None
        self.current_token = None  # 确保初始化认证令牌为None
        
        # 超时设置
        self.timeout = 30  # 秒
        
        logger.info("客户端API通信模块初始化完成", "ClientAPI.__init__")
        logger.debug("认证状态初始化: is_authenticated=False, current_token=None", "ClientAPI.__init__")
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict[str, Any]:
        """
        发送HTTP请求的通用方法
        
        Args:
            method: HTTP方法（GET, POST, DELETE等）
            endpoint: API端点
            data: 请求数据（JSON）
            params: URL参数
            
        Returns:
            服务器响应数据
        """
        # 记录请求开始
        logger.debug(f"开始准备HTTP请求", "_make_request")
        logger.debug(f"请求方法: {method}", "_make_request")
        logger.debug(f"请求端点: {endpoint}", "_make_request")
        
        # 构建完整URL
        url = f"{self.server_url}{endpoint}"
        logger.debug(f"构建完整URL: {url}", "_make_request")
        
        # 记录请求参数（隐藏敏感信息）
        if data:
            safe_data = data.copy()
            if 'password' in safe_data:
                safe_data['password'] = '***隐藏***'
            logger.debug(f"请求数据: {safe_data}", "_make_request")
        
        if params:
            logger.debug(f"URL参数: {params}", "_make_request")
        
        # 确保每次请求都使用当前令牌（如果有）
        current_headers = {}
        if self.current_token and endpoint != '/api/login':
            logger.debug(f"请求附加认证令牌: {self.current_token[:8]}...", "_make_request")
            current_headers['X-Auth-Token'] = self.current_token
        
        logger.info(f"发送HTTP请求: {method} {endpoint}", "_make_request")
        logger.debug(f"请求URL: {url}", "_make_request")
        
        try:
            # 记录请求执行开始
            logger.debug(f"开始执行HTTP请求: {method.upper()}", "_make_request")
            
            # 根据HTTP方法发送请求
            if method.upper() == 'GET':
                logger.debug("执行GET请求", "_make_request")
                response = self.session.get(url, params=params, timeout=self.timeout, headers=current_headers)
            elif method.upper() == 'POST':
                logger.debug("执行POST请求", "_make_request")
                response = self.session.post(url, json=data, params=params, timeout=self.timeout, headers=current_headers)
            elif method.upper() == 'DELETE':
                logger.debug("执行DELETE请求", "_make_request")
                response = self.session.delete(url, params=params, timeout=self.timeout, headers=current_headers)
            elif method.upper() == 'PUT':
                logger.debug("执行PUT请求", "_make_request")
                response = self.session.put(url, json=data, params=params, timeout=self.timeout, headers=current_headers)
            else:
                logger.error(f"不支持的HTTP方法: {method}", "_make_request")
                logger.operation("HTTP请求失败：不支持的方法", "_make_request", {'method': method})
                return {
                    'success': False,
                    'message': f'不支持的HTTP方法: {method}',
                    'error_code': 'UNSUPPORTED_METHOD'
                }
            
            # 记录响应接收
            logger.debug(f"HTTP请求执行完成", "_make_request")
            logger.debug(f"响应状态码: {response.status_code}", "_make_request")
            logger.debug(f"响应头信息: {dict(response.headers)}", "_make_request")
            logger.info(f"收到HTTP响应: {response.status_code}", "_make_request")
            
            # 尝试解析JSON响应
            logger.debug("开始解析JSON响应", "_make_request")
            try:
                response_data = response.json()
                logger.debug("JSON响应解析成功", "_make_request")
                logger.debug(f"响应数据大小: {len(str(response_data))} 字符", "_make_request")
                
                # 记录响应数据（隐藏敏感信息）
                safe_response = response_data.copy() if isinstance(response_data, dict) else response_data
                if isinstance(safe_response, dict) and 'token' in safe_response:
                    safe_response['token'] = '***隐藏***'
                logger.debug(f"响应数据: {safe_response}", "_make_request")
                
                # 处理登录响应，保存令牌
                if endpoint == '/api/login' and response_data.get('success') and 'token' in response_data:
                    self.current_token = response_data['token']
                    logger.debug(f"已保存登录令牌: {self.current_token[:8]}...", "_make_request")
                
            except json.JSONDecodeError as e:
                logger.error(f"JSON解析失败", "_make_request", e)
                logger.error(f"原始响应内容（前200字符）: {response.text[:200]}", "_make_request")
                logger.operation("HTTP请求失败：JSON解析错误", "_make_request", {
                    'status_code': response.status_code,
                    'error': str(e)
                })
                return {
                    'success': False,
                    'message': 'JSON解析失败',
                    'error_code': 'JSON_DECODE_ERROR',
                    'raw_response': response.text
                }
            
            # 检查HTTP状态码
            if response.status_code >= 400:
                logger.warning(f"HTTP错误状态码: {response.status_code}", "_make_request")
                logger.warning(f"错误响应数据: {response_data}", "_make_request")
                
                # 如果是认证错误，清除当前令牌
                if response.status_code == 401:
                    logger.warning("收到401未授权响应，清除当前令牌", "_make_request")
                    self.current_token = None
                    self.is_authenticated = False
            else:
                logger.debug(f"HTTP请求成功: {response.status_code}", "_make_request")
            
            # 记录操作日志
            logger.operation(
                f"HTTP请求完成: {method} {endpoint}",
                "_make_request",
                {
                    'status_code': response.status_code,
                    'success': response_data.get('success', False),
                    'url': url
                }
            )
            
            logger.debug("HTTP请求处理完成，返回响应数据", "_make_request")
            return response_data
            
        except requests.exceptions.Timeout as e:
            logger.error(f"HTTP请求超时", "_make_request", e)
            logger.error(f"请求URL: {url}", "_make_request")
            logger.error(f"超时时间: {self.timeout}秒", "_make_request")
            logger.operation("HTTP请求失败：请求超时", "_make_request", {
                'url': url,
                'timeout': self.timeout,
                'method': method
            })
            return {
                'success': False,
                'message': '请求超时',
                'error_code': 'REQUEST_TIMEOUT'
            }
            
        except requests.exceptions.ConnectionError as e:
            logger.error(f"HTTP连接错误", "_make_request", e)
            logger.error(f"请求URL: {url}", "_make_request")
            logger.error(f"服务器地址: {self.server_url}", "_make_request")
            logger.operation("HTTP请求失败：连接错误", "_make_request", {
                'url': url,
                'server_url': self.server_url,
                'method': method
            })
            return {
                'success': False,
                'message': '无法连接到服务器',
                'error_code': 'CONNECTION_ERROR'
            }
            
        except Exception as e:
            logger.error(f"HTTP请求发生未知异常", "_make_request", e)
            logger.error(f"请求URL: {url}", "_make_request")
            logger.error(f"异常类型: {type(e).__name__}", "_make_request")
            logger.operation("HTTP请求失败：未知异常", "_make_request", {
                'url': url,
                'method': method,
                'exception_type': type(e).__name__,
                'exception_message': str(e)
            })
            return {
                'success': False,
                'message': f'请求失败: {str(e)}',
                'error_code': 'REQUEST_ERROR'
            }
    
    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        用户登录
        
        Args:
            username: 用户名
            password: 密码
            
        Returns:
            登录结果
        """
        logger.info(f"尝试登录用户: {username}", "login")
        
        # 发送登录请求
        response = self._make_request('POST', '/api/login', {
            'username': username,
            'password': password
        })
        
        # 处理响应
        if response.get('success'):
            self.is_authenticated = True
            self.current_user = response.get('user', {})
            
            # 保存令牌
            if 'token' in response:
                self.current_token = response['token']
                logger.debug(f"已保存认证令牌: {self.current_token[:8]}..., 长度={len(self.current_token)}", "login")
            else:
                logger.warning("登录成功但服务器未返回令牌", "login")
                self.current_token = None
                # 返回自定义错误，因为缺少令牌无法正常工作
                return {
                    'success': False,
                    'message': '服务器未返回认证令牌',
                    'error_code': 'TOKEN_MISSING'
                }
            
            logger.info(f"用户登录成功: {username}", "login")
            logger.operation("用户登录成功", "login", {
                'username': username,
                'has_token': self.current_token is not None,
                'token_length': len(self.current_token) if self.current_token else 0
            })
        else:
            self.is_authenticated = False
            self.current_user = None
            self.current_token = None
            logger.warning(f"用户登录失败: {username} - {response.get('message')}", "login")
        
        return response
    
    def logout(self) -> Dict[str, Any]:
        """
        用户注销
        
        Returns:
            注销结果
        """
        logger.info("尝试注销用户", "logout")
        
        # 发送注销请求
        response = self._make_request('POST', '/api/logout')
        
        # 处理响应
        if response.get('success'):
            self.is_authenticated = False
            self.current_user = None
            logger.info("用户注销成功", "logout")
            logger.operation("用户注销成功", "logout")
        else:
            logger.warning(f"用户注销失败: {response.get('message')}", "logout")
        
        return response
    
    def verify_token(self) -> Dict[str, Any]:
        """
        验证用户令牌
        
        Returns:
            验证结果
        """
        logger.debug("开始验证用户令牌", "verify_token")
        
        # 记录当前认证状态
        current_auth_status = self.is_authenticated
        current_user = self.current_user.get('username', '未知') if self.current_user else '未知'
        logger.debug(f"当前认证状态: authenticated={current_auth_status}, user={current_user}", "verify_token")
        
        # 重试计数器
        retry_count = 0
        max_retries = 2
        retry_delay = 1.0  # 初始重试延迟（秒）
        
        while retry_count <= max_retries:
            try:
                # 发送验证请求
                logger.debug(f"向服务器发送令牌验证请求 (尝试 {retry_count+1}/{max_retries+1})", "verify_token")
                response = self._make_request('GET', '/api/verify-token')
                
                # 记录响应详情
                logger.debug(f"令牌验证响应: {response}", "verify_token")
                
                # 处理响应
                if response.get('success'):
                    # 更新认证状态
                    self.is_authenticated = True
                    self.current_user = response.get('user', {})
                    new_user = self.current_user.get('username', '未知')
                    
                    # 记录令牌过期时间
                    token_expires_at = self.current_user.get('token_expires_at', 0)
                    if token_expires_at:
                        current_time = time.time()
                        remaining_time = token_expires_at - current_time
                        logger.debug(f"令牌剩余有效期: {remaining_time:.1f}秒", "verify_token")
                    
                    logger.info(f"令牌验证成功，用户={new_user}", "verify_token")
                    
                    # 记录操作日志
                    logger.operation("令牌验证成功", "verify_token", {
                        'username': new_user,
                        'previous_auth_status': current_auth_status,
                        'token_expires_at': token_expires_at
                    })
                    
                    return response
                else:
                    error_message = response.get('message', '令牌验证失败')
                    error_code = response.get('error_code', 'UNKNOWN_ERROR')
                    
                    # 对于网络相关错误进行重试
                    if error_code in ['CONNECTION_ERROR', 'REQUEST_TIMEOUT'] and retry_count < max_retries:
                        retry_count += 1
                        retry_wait = retry_delay * (2 ** retry_count)  # 指数退避
                        logger.warning(f"令牌验证网络错误，将在 {retry_wait:.1f} 秒后重试 ({retry_count}/{max_retries}): {error_message}", "verify_token")
                        time.sleep(retry_wait)
                        continue
                    
                    # 令牌无效，清除认证状态
                    self.is_authenticated = False
                    self.current_user = None
                    
                    logger.warning(f"令牌验证失败: {error_message}, 代码={error_code}, 之前用户={current_user}", "verify_token")
                    
                    # 记录操作日志
                    logger.operation("令牌验证失败", "verify_token", {
                        'previous_username': current_user,
                        'error_message': error_message,
                        'error_code': error_code,
                        'retry_count': retry_count
                    })
                    
                    return response
                    
            except requests.exceptions.RequestException as e:
                # 处理请求异常（连接错误、超时等）
                if retry_count < max_retries:
                    retry_count += 1
                    retry_wait = retry_delay * (2 ** retry_count)  # 指数退避
                    logger.warning(f"令牌验证请求异常，将在 {retry_wait:.1f} 秒后重试 ({retry_count}/{max_retries}): {str(e)}", "verify_token")
                    time.sleep(retry_wait)
                    continue
                else:
                    logger.error(f"令牌验证请求异常，已达到最大重试次数", "verify_token", e)
                    logger.debug(f"异常详情: {str(e)}", "verify_token")
                    
                    # 记录操作日志
                    logger.operation("令牌验证请求异常", "verify_token", {
                        'previous_username': current_user,
                        'exception': str(e),
                        'retry_count': retry_count
                    })
                    
                    # 网络异常情况下保持当前认证状态不变
                    return {
                        'success': False,
                        'message': f'验证令牌时发生网络异常: {str(e)}',
                        'error_code': 'NETWORK_ERROR'
                    }
                    
            except Exception as e:
                logger.error(f"验证令牌过程发生未知异常", "verify_token", e)
                logger.debug(f"异常详情: {str(e)}", "verify_token")
                
                # 记录操作日志
                logger.operation("令牌验证异常", "verify_token", {
                    'previous_username': current_user,
                    'exception': str(e)
                })
                
                # 未知异常情况下保持当前认证状态不变
                return {
                    'success': False,
                    'message': f'验证令牌时发生异常: {str(e)}',
                    'error_code': 'VERIFICATION_EXCEPTION'
                }
    
    def list_instances(self, group_id: Optional[str] = None) -> Dict[str, Any]:
        """
        获取实例列表
        
        Args:
            group_id: 分组ID（可选）
            
        Returns:
            实例列表
        """
        logger.info("获取实例列表", "list_instances")
        
        # 构建参数
        params = {}
        if group_id:
            params['group_id'] = group_id
            logger.debug(f"按分组筛选: {group_id}", "list_instances")
        
        # 发送请求
        response = self._make_request('GET', '/api/instances', params=params)
        
        # 处理响应
        if response.get('success'):
            instances = response.get('instances', [])
            logger.info(f"获取到 {len(instances)} 个实例", "list_instances")
        else:
            logger.warning(f"获取实例列表失败: {response.get('message')}", "list_instances")
        
        return response
    
    def get_instance(self, instance_id: str) -> Dict[str, Any]:
        """
        获取实例详情
        
        Args:
            instance_id: 实例ID
            
        Returns:
            实例详情
        """
        logger.info(f"获取实例详情: {instance_id}", "get_instance")
        
        # 发送请求
        response = self._make_request('GET', f'/api/instances/{instance_id}')
        
        # 处理响应
        if response.get('success'):
            logger.info(f"获取实例详情成功: {instance_id}", "get_instance")
        else:
            logger.warning(f"获取实例详情失败: {response.get('message')}", "get_instance")
        
        return response
    
    def inject_javascript(self, instance_id: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        注入JavaScript代码
        
        Args:
            instance_id: 实例ID
            file_path: JavaScript文件路径（可选）
            
        Returns:
            注入结果
        """
        logger.info(f"向实例 {instance_id} 注入JavaScript", "inject_javascript")
        
        # 构建参数
        data = {}
        if file_path:
            data['file_path'] = file_path
            logger.debug(f"使用文件: {file_path}", "inject_javascript")
        
        # 发送请求
        response = self._make_request('POST', f'/api/instances/{instance_id}/inject', data=data)
        
        # 处理响应
        if response.get('success'):
            logger.info(f"JavaScript注入成功: {instance_id}", "inject_javascript")
            logger.operation("JavaScript注入成功", "inject_javascript", {
                'instance_id': instance_id,
                'file_path': file_path
            })
        else:
            logger.warning(f"JavaScript注入失败: {response.get('message')}", "inject_javascript")
        
        return response
    
    def execute_command(self, instance_id: str, command: str, args: Optional[List] = None) -> Dict[str, Any]:
        """
        在实例中执行命令
        
        Args:
            instance_id: 实例ID
            command: 要执行的命令
            args: 命令参数（可选）
            
        Returns:
            执行结果
        """
        logger.info(f"执行命令: 实例={instance_id}, 命令={command}", "execute_command")
        
        # 记录参数详情
        if args:
            logger.debug(f"命令参数: {args}", "execute_command")
        
        try:
            # 准备执行数据
            execute_data = {
                'command': command
            }
            
            if args:
                execute_data['args'] = args
            
            logger.debug(f"准备执行数据: {execute_data}", "execute_command")
            
            # 发送命令执行请求
            start_time = time.time()
            result = self._make_request('POST', f'/api/instances/{instance_id}/execute', data=execute_data)
            execution_time = time.time() - start_time
            
            # 记录执行时间
            logger.debug(f"命令执行请求耗时: {execution_time:.3f}秒", "execute_command")
            
            # 处理响应
            if result.get('success'):
                # 命令执行成功
                command_result = result.get('result')
                result_type = type(command_result).__name__
                server_execution_time = result.get('execution_time', 0)
                
                logger.info(f"命令执行成功: {instance_id}, 命令={command}, 服务器耗时={server_execution_time:.3f}秒", "execute_command")
                logger.debug(f"命令执行结果类型: {result_type}", "execute_command")
                
                # 记录操作日志
                logger.operation("命令执行成功", "execute_command", {
                    'instance_id': instance_id,
                    'command': command,
                    'execution_time': server_execution_time,
                    'result_type': result_type,
                    'request_time': execution_time
                })
            else:
                # 命令执行失败
                error_message = result.get('message', '执行失败')
                error_code = result.get('error_code', 'UNKNOWN_ERROR')
                
                logger.warning(f"命令执行失败: {instance_id}, 命令={command}, 错误={error_message}, 代码={error_code}", "execute_command")
                
                # 记录详细的错误信息
                logger.debug(f"命令执行失败详情: {result}", "execute_command")
                
                # 记录操作日志
                logger.operation("命令执行失败", "execute_command", {
                    'instance_id': instance_id,
                    'command': command,
                    'error_message': error_message,
                    'error_code': error_code,
                    'request_time': execution_time
                })
            
            return result
            
        except Exception as e:
            logger.error(f"执行命令过程发生异常: {instance_id}, 命令={command}", "execute_command", e)
            logger.debug(f"异常详情: {str(e)}", "execute_command")
            
            # 记录操作日志
            logger.operation("命令执行异常", "execute_command", {
                'instance_id': instance_id,
                'command': command,
                'exception': str(e)
            })
            
            return {
                'success': False,
                'message': f'执行命令时发生异常: {str(e)}',
                'error_code': 'EXECUTION_EXCEPTION',
                'command': command
            }
    
    def get_js_modules(self) -> Dict[str, Any]:
        """
        获取JavaScript模块列表
        
        Returns:
            模块列表结果
        """
        logger.info("获取JavaScript模块列表", "get_js_modules")
        
        # 发送获取JavaScript模块列表请求
        result = self._make_request('GET', '/api/js-modules')
        
        if result.get('success'):
            modules = result.get('modules', [])
            logger.info(f"JavaScript模块列表获取成功，数量: {len(modules)}", "get_js_modules")
            log_operation(f"JavaScript模块列表获取成功，数量: {len(modules)}", "get_js_modules", {'total': len(modules)})
        else:
            error_message = result.get('message', '获取模块列表失败')
            logger.warning(f"JavaScript模块列表获取失败: {error_message}", "get_js_modules")
        
        return result
        
    # DevTools相关方法
    
    def enable_devtools(self, instance_id: str) -> Dict[str, Any]:
        """
        启用实例的DevTools调试功能
        
        Args:
            instance_id: 实例ID
            
        Returns:
            启用结果
        """
        logger.info(f"启用实例DevTools调试功能: {instance_id}", "enable_devtools")
        
        # 检查参数
        if not instance_id:
            logger.error("实例ID为空", "enable_devtools")
            return {
                'success': False,
                'message': '实例ID不能为空',
                'error_code': 'INVALID_INSTANCE_ID'
            }
        
        # 构建请求URL
        url = f"/api/instances/{instance_id}/devtools/enable"
        logger.debug(f"请求URL: {url}", "enable_devtools")
        
        try:
            # 发送启用DevTools请求
            result = self._make_request('POST', url)
            
            if result.get('success'):
                logger.info(f"DevTools调试功能启用成功: {instance_id}", "enable_devtools")
                
                # 记录调试信息
                debugging_info = result.get('debugging_info', {})
                if debugging_info:
                    ws_url = debugging_info.get('ws_url', 'unknown')
                    debugging_url = debugging_info.get('debugging_url', 'unknown')
                    logger.debug(f"调试信息: debugging_url={debugging_url}, ws_url={ws_url}", "enable_devtools")
                
                return result
            else:
                error_msg = result.get('message', 'DevTools调试功能启用失败')
                error_code = result.get('error_code', 'DEVTOOLS_ENABLE_FAILED')
                logger.warning(f"DevTools调试功能启用失败: {instance_id} - {error_msg}", "enable_devtools")
                
                # 尝试获取更多错误信息
                if 'error_details' in result:
                    logger.debug(f"错误详情: {result['error_details']}", "enable_devtools")
                
                # 尝试第二次请求
                logger.debug("第一次请求失败，尝试第二次请求", "enable_devtools")
                second_result = self._make_request('POST', url)
                
                if second_result.get('success'):
                    logger.info(f"第二次尝试DevTools调试功能启用成功: {instance_id}", "enable_devtools")
                    return second_result
                else:
                    second_error = second_result.get('message', '未知错误')
                    logger.warning(f"第二次尝试也失败: {second_error}", "enable_devtools")
                
                return {
                    'success': False,
                    'message': error_msg,
                    'error_code': error_code,
                    'first_attempt': result,
                    'second_attempt': second_result if 'second_result' in locals() else None
                }
                
        except Exception as e:
            logger.error("启用DevTools调试功能时发生异常", "enable_devtools", e)
            return {
                'success': False,
                'message': f'启用DevTools调试功能时发生异常: {str(e)}',
                'error_code': 'DEVTOOLS_ENABLE_EXCEPTION'
            }
    
    def get_devtools_info(self, instance_id: str) -> Dict[str, Any]:
        """
        获取实例的DevTools调试信息
        
        Args:
            instance_id: 实例ID
            
        Returns:
            调试信息
        """
        logger.debug(f"获取DevTools调试信息: {instance_id}", "get_devtools_info")
        
        # 发送获取DevTools信息请求
        result = self._make_request('GET', f'/api/instances/{instance_id}/devtools/info')
        
        if result.get('success'):
            logger.debug(f"DevTools调试信息获取成功: {instance_id}", "get_devtools_info")
            log_operation(f"DevTools调试信息获取成功: {instance_id}", "get_devtools_info")
        else:
            error_message = result.get('message', '获取信息失败')
            logger.warning(f"DevTools调试信息获取失败: {instance_id} - {error_message}", "get_devtools_info")
        
        return result
    
    def create_devtools_connection(self, instance_id: str) -> Dict[str, Any]:
        """
        创建DevTools WebSocket连接
        
        Args:
            instance_id: 实例ID
            
        Returns:
            连接信息
        """
        logger.info(f"创建DevTools WebSocket连接: {instance_id}", "create_devtools_connection")
        
        # 发送创建DevTools连接请求
        result = self._make_request('POST', f'/api/instances/{instance_id}/devtools/connect')
        
        if result.get('success'):
            logger.info(f"DevTools WebSocket连接创建成功: {instance_id}", "create_devtools_connection")
            log_operation(f"DevTools WebSocket连接创建成功: {instance_id}", "create_devtools_connection")
        else:
            error_message = result.get('message', '创建连接失败')
            logger.warning(f"DevTools WebSocket连接创建失败: {instance_id} - {error_message}", "create_devtools_connection")
        
        return result
    
    def disable_devtools(self, instance_id: str) -> Dict[str, Any]:
        """
        禁用实例的DevTools调试功能
        
        Args:
            instance_id: 实例ID
            
        Returns:
            禁用结果
        """
        logger.info(f"禁用DevTools调试功能: {instance_id}", "disable_devtools")
        
        # 发送禁用DevTools请求
        result = self._make_request('POST', f'/api/instances/{instance_id}/devtools/disable')
        
        if result.get('success'):
            logger.info(f"DevTools调试功能禁用成功: {instance_id}", "disable_devtools")
            log_operation(f"DevTools调试功能禁用成功: {instance_id}", "disable_devtools")
        else:
            error_message = result.get('message', '禁用失败')
            logger.warning(f"DevTools调试功能禁用失败: {instance_id} - {error_message}", "disable_devtools")
        
        return result 