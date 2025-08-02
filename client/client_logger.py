#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
客户端日志模块
提供详细的日志记录功能，支持多级别日志和操作记录
"""

import os
import sys
import time
import logging
import traceback
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Optional

# 日志级别映射
LOG_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL
}

# 单例日志实例
_client_logger_instance = None

class ClientLogger:
    """客户端日志类"""
    
    def __init__(self, log_dir: str = 'logs', log_level: str = 'debug', clear_on_start: bool = False):
        """
        初始化日志系统
        
        Args:
            log_dir: 日志目录
            log_level: 日志级别
            clear_on_start: 是否在启动时清空日志文件
        """
        # 创建日志目录
        self.log_dir = Path(log_dir)
        if not self.log_dir.exists():
            self.log_dir.mkdir(exist_ok=True)
        
        # 设置日志级别
        self.log_level = LOG_LEVELS.get(log_level.lower(), logging.DEBUG)
        
        # 创建主日志记录器
        self.logger = logging.getLogger('client')
        self.logger.setLevel(self.log_level)
        
        # 清除已有的处理器
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        console_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # 创建文件处理器
        log_file = self.log_dir / 'client.log'
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(self.log_level)
        file_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] [%(module)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
        
        # 创建操作日志记录器
        self.operation_logger = logging.getLogger('client.operation')
        self.operation_logger.setLevel(logging.INFO)
        
        # 清除已有的处理器
        if self.operation_logger.handlers:
            self.operation_logger.handlers.clear()
        
        # 创建操作日志文件处理器
        operation_log_file = self.log_dir / 'client_operations.log'
        operation_file_handler = RotatingFileHandler(
            operation_log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        operation_file_handler.setLevel(logging.INFO)
        operation_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        operation_file_handler.setFormatter(operation_format)
        self.operation_logger.addHandler(operation_file_handler)
        
        # 如果启动时需要清空日志文件，在设置完成后清空
        if clear_on_start:
            self._clear_log_files()
        
        # 记录初始化信息
        self.info("客户端日志系统初始化完成", "ClientLogger.__init__")
    
    def _clear_log_files(self):
        """清空客户端日志文件"""
        try:
            print("开始清空客户端日志文件...")
            
            # 先关闭所有现有的日志处理器
            if hasattr(self, 'logger') and self.logger:
                for handler in self.logger.handlers[:]:
                    handler.close()
                    self.logger.removeHandler(handler)
            if hasattr(self, 'operation_logger') and self.operation_logger:
                for handler in self.operation_logger.handlers[:]:
                    handler.close()
                    self.operation_logger.removeHandler(handler)
            
            # 定义要清空的日志文件列表
            log_files = [
                'client.log',
                'client_operations.log'
            ]
            
            # 遍历并清空每个日志文件
            for log_file in log_files:
                log_path = self.log_dir / log_file
                try:
                    # 直接创建空文件（覆盖原文件）
                    with open(log_path, 'w', encoding='utf-8') as f:
                        f.write('')  # 清空文件内容
                    print(f"已清空客户端日志文件: {log_path}")
                except Exception as e:
                    print(f"清空客户端日志文件失败 {log_path}: {e}")
            
            print("客户端日志文件清空完成")
                    
        except Exception as e:
            print(f"清空客户端日志文件过程中发生错误: {e}")
    
    def debug(self, message: str, module: str = None, exc_info: Exception = None) -> None:
        """
        记录调试日志
        
        Args:
            message: 日志消息
            module: 模块名称
            exc_info: 异常信息
        """
        module_prefix = f"[{module}] " if module else ""
        self.logger.debug(f"{module_prefix}{message}", exc_info=exc_info)
    
    def info(self, message: str, module: str = None) -> None:
        """
        记录信息日志
        
        Args:
            message: 日志消息
            module: 模块名称
        """
        module_prefix = f"[{module}] " if module else ""
        self.logger.info(f"{module_prefix}{message}")
    
    def warning(self, message: str, module: str = None) -> None:
        """
        记录警告日志
        
        Args:
            message: 日志消息
            module: 模块名称
        """
        module_prefix = f"[{module}] " if module else ""
        self.logger.warning(f"{module_prefix}{message}")
    
    def error(self, message: str, module: str = None, exc_info: Exception = None) -> None:
        """
        记录错误日志
        
        Args:
            message: 日志消息
            module: 模块名称
            exc_info: 异常信息
        """
        module_prefix = f"[{module}] " if module else ""
        if exc_info:
            error_details = ''.join(traceback.format_exception(type(exc_info), exc_info, exc_info.__traceback__))
            self.logger.error(f"{module_prefix}{message}\n{error_details}")
        else:
            self.logger.error(f"{module_prefix}{message}")
    
    def operation(self, message: str, module: str = None, details: Dict[str, Any] = None) -> None:
        """
        记录操作日志
        
        Args:
            message: 日志消息
            module: 模块名称
            details: 操作详情
        """
        module_prefix = f"[{module}] " if module else ""
        log_message = f"{module_prefix}{message}"
        
        if details:
            detail_str = " | ".join([f"{k}={v}" for k, v in details.items()])
            log_message += f" | {detail_str}"
        
        self.operation_logger.info(log_message)

def get_client_logger(clear_on_start: bool = False) -> ClientLogger:
    """
    获取客户端日志实例（单例模式）
    
    Args:
        clear_on_start: 是否在启动时清空日志文件
    
    Returns:
        ClientLogger实例
    """
    global _client_logger_instance
    
    if _client_logger_instance is None:
        _client_logger_instance = ClientLogger(clear_on_start=clear_on_start)
    elif clear_on_start:
        # 如果需要清空且实例已存在，直接清空文件
        _client_logger_instance._clear_log_files()
    
    return _client_logger_instance

# 导出便捷函数
def log_debug(message: str, module: str = None, exc_info: Exception = None) -> None:
    """记录调试日志"""
    get_client_logger().debug(message, module, exc_info)

def log_info(message: str, module: str = None) -> None:
    """记录信息日志"""
    get_client_logger().info(message, module)

def log_warning(message: str, module: str = None) -> None:
    """记录警告日志"""
    get_client_logger().warning(message, module)

def log_error(message: str, module: str = None, exc_info: Exception = None) -> None:
    """记录错误日志"""
    get_client_logger().error(message, module, exc_info)

def log_operation(message: str, module: str = None, details: Dict[str, Any] = None) -> None:
    """记录操作日志"""
    get_client_logger().operation(message, module, details) 