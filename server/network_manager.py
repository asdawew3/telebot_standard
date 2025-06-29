#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
网络管理模块
负责网络配置、端口管理和Chrome浏览器网络参数设置
简化版本，只提供基本功能
"""

import socket
import platform
import time
import os
from typing import Dict, Any, List, Optional

from .logger import get_server_logger

# 获取服务端日志实例
logger = get_server_logger()

class NetworkManager:
    """网络管理器"""
    
    def __init__(self):
        """初始化网络管理器"""
        logger.info("初始化网络管理器", "NetworkManager.__init__")
        
        # 系统信息
        self.system = platform.system().lower()
        self.is_windows = self.system == 'windows'
        self.is_linux = self.system == 'linux'
        
        logger.debug(f"检测到操作系统: {self.system}", "NetworkManager.__init__")
        logger.info("网络管理器初始化完成", "NetworkManager.__init__")
    
    def check_port_accessibility(self, port: int) -> Dict[str, Any]:
        """
        检查端口可访问性
        
        Args:
            port: 端口号
            
        Returns:
            检查结果字典
        """
        logger.info(f"检查端口可访问性: {port}", "NetworkManager.check_port_accessibility")
        
        result = {
            'port': port,
            'is_listening': False,
            'local_ip': self._get_local_ip(),
            'can_bind': False,
            'suggestions': []
        }
        
        try:
            # 检查端口是否正在监听
            logger.debug(f"检查端口监听状态: {port}", "NetworkManager.check_port_accessibility")
            result['is_listening'] = self._is_port_listening(port)
            logger.debug(f"端口监听状态: {result['is_listening']}", "NetworkManager.check_port_accessibility")
            
            # 检查是否可以绑定端口
            logger.debug(f"检查端口绑定能力: {port}", "NetworkManager.check_port_accessibility")
            result['can_bind'] = self._can_bind_port(port)
            logger.debug(f"端口绑定能力: {result['can_bind']}", "NetworkManager.check_port_accessibility")
            
            # 生成建议
            logger.debug("生成网络配置建议", "NetworkManager.check_port_accessibility")
            result['suggestions'] = self._generate_suggestions(result)
            
            logger.info(f"端口可访问性检查完成: {port}", "NetworkManager.check_port_accessibility")
            
        except Exception as e:
            logger.error(f"检查端口可访问性失败: {port}", "NetworkManager.check_port_accessibility", e)
            result['error'] = str(e)
        
        return result
    
    def _get_local_ip(self) -> str:
        """获取本地IP地址"""
        logger.debug("获取本地IP地址", "NetworkManager._get_local_ip")
        
        try:
            # 通过连接外部地址获取本地IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                local_ip = s.getsockname()[0]
            
            logger.debug(f"本地IP地址: {local_ip}", "NetworkManager._get_local_ip")
            return local_ip
            
        except Exception as e:
            logger.warning(f"获取本地IP失败: {e}", "NetworkManager._get_local_ip")
            return '127.0.0.1'
    
    def _is_port_listening(self, port: int) -> bool:
        """检查端口是否正在监听"""
        logger.debug(f"检查端口监听状态: {port}", "NetworkManager._is_port_listening")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(('127.0.0.1', port))
                is_listening = result == 0
                
            logger.debug(f"端口 {port} 监听状态: {is_listening}", "NetworkManager._is_port_listening")
            return is_listening
            
        except Exception as e:
            logger.warning(f"检查端口监听状态失败: {e}", "NetworkManager._is_port_listening")
            return False
    
    def _can_bind_port(self, port: int) -> bool:
        """检查是否可以绑定端口"""
        logger.debug(f"检查端口绑定能力: {port}", "NetworkManager._can_bind_port")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                can_bind = True
                
            logger.debug(f"端口 {port} 可以绑定", "NetworkManager._can_bind_port")
            return can_bind
            
        except socket.error as e:
            if e.errno in [10048, 98]:  # Address already in use
                logger.debug(f"端口 {port} 已被占用", "NetworkManager._can_bind_port")
                return False
            else:
                logger.warning(f"端口绑定检查失败: {e}", "NetworkManager._can_bind_port")
                return False
    
    def _generate_suggestions(self, port_info: Dict[str, Any]) -> List[str]:
        """生成网络配置建议"""
        logger.debug("生成网络配置建议", "NetworkManager._generate_suggestions")
        
        suggestions = []
        
        # 检查端口状态并给出建议
        if not port_info['is_listening'] and port_info['can_bind']:
            suggestions.append("端口可用，服务器可以正常启动")
            logger.debug("添加建议: 端口可用", "NetworkManager._generate_suggestions")
        
        if port_info['is_listening']:
            suggestions.append("端口已在使用中，可能有其他服务正在运行")
            logger.debug("添加建议: 端口已占用", "NetworkManager._generate_suggestions")
        
        if not port_info['can_bind']:
            suggestions.append("端口无法绑定，请检查是否有权限问题或端口冲突")
            logger.debug("添加建议: 端口无法绑定", "NetworkManager._generate_suggestions")
        
        # 添加防火墙相关建议
        if self.is_windows:
            suggestions.append("如需外部访问，请在Windows防火墙中允许该端口")
        elif self.is_linux:
            suggestions.append("如需外部访问，请配置防火墙规则（如ufw、iptables）")
        
        # 添加通用网络建议
        suggestions.append("确保服务器监听地址设置为 0.0.0.0 以允许外部连接")
        
        logger.debug(f"生成 {len(suggestions)} 条建议", "NetworkManager._generate_suggestions")
        return suggestions
    
    # 网络日志相关功能 (简化版)
    def log_network_event(self, level: str, category: str, message: str, 
                         instance_id: Optional[str] = None, **details) -> None:
        """
        记录网络事件 (简化版)
        
        Args:
            level: 日志级别（DEBUG, INFO, WARNING, ERROR）
            category: 事件分类
            message: 日志消息
            instance_id: 实例ID（可选）
            **details: 详细信息
        """
        try:
            # 构建日志消息
            log_message = f"[NETWORK-{category}]"
            if instance_id:
                log_message += f" [{instance_id}]"
            log_message += f" {message}"
            
            # 记录到主日志
            if level.upper() == 'DEBUG':
                logger.debug(log_message, "NetworkManager")
            elif level.upper() == 'INFO':
                logger.info(log_message, "NetworkManager")
            elif level.upper() == 'WARNING':
                logger.warning(log_message, "NetworkManager")
            elif level.upper() == 'ERROR':
                logger.error(log_message, "NetworkManager")
                
        except Exception as e:
            logger.error(f"记录网络事件失败: {e}", "NetworkManager.log_network_event", e)
    
    def log_connection_attempt(self, instance_id: str, url: str, method: str = 'GET') -> None:
        """记录连接尝试"""
        self.log_network_event(
            level='INFO',
            category='CONNECTION',
            message=f"尝试连接到 {url}",
            instance_id=instance_id,
            url=url,
            method=method
        )
    
    def log_connection_success(self, instance_id: str, url: str, response_time: float) -> None:
        """记录连接成功"""
        self.log_network_event(
            level='INFO',
            category='CONNECTION',
            message=f"连接成功: {url} (耗时: {response_time:.2f}s)",
            instance_id=instance_id,
            url=url,
            response_time=response_time
        )
    
    def log_connection_failure(self, instance_id: str, url: str, error: str) -> None:
        """记录连接失败"""
        self.log_network_event(
            level='ERROR',
            category='CONNECTION',
            message=f"连接失败: {url} - {error}",
            instance_id=instance_id,
            url=url,
            error=error
        )
    
    def log_chrome_option(self, instance_id: str, option: str, reason: str) -> None:
        """记录Chrome选项"""
        self.log_network_event(
            level='INFO',
            category='CHROME_OPTION',
            message=f"添加Chrome选项: {option} - {reason}",
            instance_id=instance_id,
            option=option,
            reason=reason
        )
    
    # Chrome网络选项 (简化版)
    def get_chrome_network_options(self) -> List[str]:
        """
        获取Chrome网络选项 (简化版)
        
        Returns:
            Chrome启动选项列表
        """
        logger.info("获取Chrome网络选项", "NetworkManager.get_chrome_network_options")
        
        # 基本选项
        options = [
            '--no-sandbox',
            '--disable-web-security',
            '--ignore-certificate-errors',
            '--allow-running-insecure-content',
            '--disable-extensions',
            '--no-proxy-server'
        ]
        
        # 针对不同系统的选项
        if self.is_windows:
            options.append('--disable-gpu')
        
        if self.is_linux:
            options.extend([
                '--disable-dev-shm-usage',
                '--disable-setuid-sandbox'
            ])
        
        logger.info(f"生成 {len(options)} 个Chrome网络选项", "NetworkManager.get_chrome_network_options")
        return options
    
    def get_minimal_chrome_options(self) -> List[str]:
        """
        获取最小Chrome选项集
        
        Returns:
            最小Chrome启动选项列表
        """
        return [
            '--no-sandbox',
            '--disable-web-security',
            '--ignore-certificate-errors'
        ]

# 全局网络管理器实例
_network_manager = None

def get_network_manager() -> NetworkManager:
    """获取全局网络管理器实例"""
    global _network_manager
    
    if _network_manager is None:
        logger.info("创建全局网络管理器实例", "get_network_manager")
        _network_manager = NetworkManager()
    else:
        logger.debug("返回现有网络管理器实例", "get_network_manager")
    
    return _network_manager 