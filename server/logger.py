#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
统一日志管理系统
提供详细的日志记录功能，服务端和客户端分别输出到不同的日志文件
控制台不显示日志，只输出到文件方便错误定位
"""

import os
import sys
import time
import logging
import threading
from datetime import datetime
from typing import Optional, Any
from logging.handlers import RotatingFileHandler

class SystemLogger:
    """系统日志管理器"""
    
    def __init__(self, log_type: str = 'server', log_dir: str = 'logs', clear_on_start: bool = False):
        """
        初始化日志管理器
        
        Args:
            log_type: 日志类型 ('server' 或 'client')
            log_dir: 日志目录
            clear_on_start: 是否在启动时清空日志文件
        """
        # 设置日志类型和目录
        self.log_type = log_type  # 记录日志类型用于标识
        self.log_dir = log_dir    # 日志输出目录
        self.logger = None        # 主要日志记录器
        self.detail_logger = None # 详细日志记录器
        self.error_logger = None  # 错误日志记录器
        self.operation_logger = None  # 操作日志记录器
        
        # 创建日志目录
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        # 如果启动时需要清空日志文件，先清空再设置
        if clear_on_start:
            self._clear_log_files()
        else:
            # 正常初始化日志系统
            self._setup_logging()
        
        # 记录初始化完成
        self.info("日志系统初始化完成", "SystemLogger.__init__")
    
    def _clear_log_files(self):
        """清空当前类型的所有日志文件"""
        try:
            print(f"开始清空{self.log_type}日志文件...")
            
            # 先关闭所有现有的日志处理器
            if self.logger:
                for handler in self.logger.handlers[:]:
                    handler.close()
                    self.logger.removeHandler(handler)
            if self.detail_logger:
                for handler in self.detail_logger.handlers[:]:
                    handler.close()
                    self.detail_logger.removeHandler(handler)
            if self.error_logger:
                for handler in self.error_logger.handlers[:]:
                    handler.close()
                    self.error_logger.removeHandler(handler)
            if self.operation_logger:
                for handler in self.operation_logger.handlers[:]:
                    handler.close()
                    self.operation_logger.removeHandler(handler)
            
            # 定义要清空的日志文件列表
            log_files = [
                f'{self.log_type}_main.log',
                f'{self.log_type}_detail.log', 
                f'{self.log_type}_error.log',
                f'{self.log_type}_operation.log'
            ]
            
            # 遍历并清空每个日志文件
            for log_file in log_files:
                log_path = os.path.join(self.log_dir, log_file)
                try:
                    # 直接创建空文件（覆盖原文件）
                    with open(log_path, 'w', encoding='utf-8') as f:
                        f.write('')  # 清空文件内容
                    print(f"已清空日志文件: {log_path}")
                except Exception as e:
                    print(f"清空日志文件失败 {log_path}: {e}")
            
            # 重新设置日志配置
            self._setup_logging()
            print(f"{self.log_type}日志文件清空完成")
                    
        except Exception as e:
            print(f"清空日志文件过程中发生错误: {e}")
    
    def _setup_logging(self):
        """设置日志配置"""
        try:
            # 创建日志目录
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)  # 创建日志目录
                
            # 设置日志文件路径（不使用日期后缀）
            main_log_file = os.path.join(self.log_dir, f'{self.log_type}_main.log')
            detail_log_file = os.path.join(self.log_dir, f'{self.log_type}_detail.log')
            error_log_file = os.path.join(self.log_dir, f'{self.log_type}_error.log')
            operation_log_file = os.path.join(self.log_dir, f'{self.log_type}_operation.log')
            
            # 创建日志格式
            detailed_formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] [%(funcName)s:%(lineno)d] [PID:%(process)d] [TID:%(thread)d] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            # 设置主要日志记录器
            self.logger = logging.getLogger(f'{self.log_type}_main')
            self.logger.setLevel(logging.DEBUG)  # 设置最低日志级别
            
            # 清除现有的处理器防止重复
            for handler in self.logger.handlers[:]:
                self.logger.removeHandler(handler)
            
            # 主要日志文件处理器（大小限制20MB，保留5个备份）
            main_handler = RotatingFileHandler(
                main_log_file, maxBytes=20*1024*1024, backupCount=5, encoding='utf-8'
            )
            main_handler.setFormatter(detailed_formatter)
            main_handler.setLevel(logging.INFO)
            self.logger.addHandler(main_handler)
            
            # 设置详细日志记录器
            self.detail_logger = logging.getLogger(f'{self.log_type}_detail')
            self.detail_logger.setLevel(logging.DEBUG)
            
            # 清除现有的处理器
            for handler in self.detail_logger.handlers[:]:
                self.detail_logger.removeHandler(handler)
            
            # 详细日志文件处理器（大小限制50MB，保留10个备份）
            detail_handler = RotatingFileHandler(
                detail_log_file, maxBytes=50*1024*1024, backupCount=10, encoding='utf-8'
            )
            detail_handler.setFormatter(detailed_formatter)
            detail_handler.setLevel(logging.DEBUG)
            self.detail_logger.addHandler(detail_handler)
            
            # 设置错误日志记录器
            self.error_logger = logging.getLogger(f'{self.log_type}_error')
            self.error_logger.setLevel(logging.ERROR)
            
            # 清除现有的处理器
            for handler in self.error_logger.handlers[:]:
                self.error_logger.removeHandler(handler)
            
            # 错误日志文件处理器（大小限制10MB，保留20个备份）
            error_handler = RotatingFileHandler(
                error_log_file, maxBytes=10*1024*1024, backupCount=20, encoding='utf-8'
            )
            error_handler.setFormatter(detailed_formatter)
            error_handler.setLevel(logging.ERROR)
            self.error_logger.addHandler(error_handler)
            
            # 设置操作日志记录器
            self.operation_logger = logging.getLogger(f'{self.log_type}_operation')
            self.operation_logger.setLevel(logging.DEBUG)
            
            # 清除现有的处理器
            for handler in self.operation_logger.handlers[:]:
                self.operation_logger.removeHandler(handler)
            
            # 操作日志文件处理器（大小限制30MB，保留15个备份）
            operation_handler = RotatingFileHandler(
                operation_log_file, maxBytes=30*1024*1024, backupCount=15, encoding='utf-8'
            )
            operation_handler.setFormatter(detailed_formatter)
            operation_handler.setLevel(logging.DEBUG)
            self.operation_logger.addHandler(operation_handler)
            
            # 禁用控制台输出（根据用户要求）
            self.logger.propagate = False
            self.detail_logger.propagate = False
            self.error_logger.propagate = False
            self.operation_logger.propagate = False
            
        except Exception as e:
            # 如果日志系统初始化失败，输出到控制台
            print(f"日志系统初始化失败: {e}")
            raise
    
    def _get_caller_info(self, operation_name: str = "") -> str:
        """获取调用者信息"""
        try:
            # 获取调用栈信息
            frame = sys._getframe(2)  # 获取调用者的调用者（跳过当前方法和info/error等方法）
            
            # 提取文件名、函数名、行号
            filename = os.path.basename(frame.f_code.co_filename)
            function_name = frame.f_code.co_name
            line_number = frame.f_lineno
            
            # 构建调用者信息字符串
            caller_info = f"[{filename}:{function_name}:{line_number}]"
            
            # 如果提供了操作名，添加到信息中
            if operation_name:
                caller_info += f"[{operation_name}]"
            
            return caller_info
            
        except Exception as e:
            # 如果获取调用者信息失败，返回默认信息
            return f"[获取调用者信息失败: {e}]"
    
    def debug(self, message: str, operation_name: str = ""):
        """记录调试级别日志"""
        try:
            # 获取调用者信息
            caller_info = self._get_caller_info(operation_name)
            
            # 构建完整日志消息
            full_message = f"{caller_info} {message}"
            
            # 写入详细日志
            if self.detail_logger:
                self.detail_logger.debug(full_message)
                
        except Exception as e:
            # 日志记录失败时的处理
            self._handle_logging_error("debug", message, e)
    
    def info(self, message: str, operation_name: str = ""):
        """记录信息级别日志"""
        try:
            # 获取调用者信息
            caller_info = self._get_caller_info(operation_name)
            
            # 构建完整日志消息
            full_message = f"{caller_info} {message}"
            
            # 写入主要日志
            if self.logger:
                self.logger.info(full_message)
                
            # 同时写入详细日志
            if self.detail_logger:
                self.detail_logger.info(full_message)
                
        except Exception as e:
            # 日志记录失败时的处理
            self._handle_logging_error("info", message, e)
    
    def warning(self, message: str, operation_name: str = ""):
        """记录警告级别日志"""
        try:
            # 获取调用者信息
            caller_info = self._get_caller_info(operation_name)
            
            # 构建完整日志消息
            full_message = f"{caller_info} {message}"
            
            # 写入主要日志
            if self.logger:
                self.logger.warning(full_message)
                
            # 同时写入详细日志
            if self.detail_logger:
                self.detail_logger.warning(full_message)
                
        except Exception as e:
            # 日志记录失败时的处理
            self._handle_logging_error("warning", message, e)
    
    def error(self, message: str, operation_name: str = "", exception: Optional[Exception] = None):
        """记录错误级别日志"""
        try:
            # 获取调用者信息
            caller_info = self._get_caller_info(operation_name)
            
            # 构建完整日志消息
            full_message = f"{caller_info} {message}"
            
            # 如果提供了异常信息，添加异常详情
            if exception:
                full_message += f" | 异常详情: {str(exception)}"
                
                # 添加异常类型信息
                exception_type = type(exception).__name__
                full_message += f" | 异常类型: {exception_type}"
            
            # 写入主要日志
            if self.logger:
                self.logger.error(full_message)
                
            # 写入详细日志
            if self.detail_logger:
                self.detail_logger.error(full_message)
                
            # 写入错误日志
            if self.error_logger:
                self.error_logger.error(full_message)
                
        except Exception as e:
            # 日志记录失败时的处理
            self._handle_logging_error("error", message, e)
    
    def critical(self, message: str, operation_name: str = "", exception: Optional[Exception] = None):
        """记录关键错误级别日志"""
        try:
            # 获取调用者信息
            caller_info = self._get_caller_info(operation_name)
            
            # 构建完整日志消息
            full_message = f"【CRITICAL】{caller_info} {message}"
            
            # 如果提供了异常信息，添加异常详情
            if exception:
                full_message += f" | 异常详情: {str(exception)}"
                
                # 添加异常类型信息
                exception_type = type(exception).__name__
                full_message += f" | 异常类型: {exception_type}"
            
            # 写入所有日志文件
            if self.logger:
                self.logger.critical(full_message)
            if self.detail_logger:
                self.detail_logger.critical(full_message)
            if self.error_logger:
                self.error_logger.critical(full_message)
                
        except Exception as e:
            # 日志记录失败时的处理
            self._handle_logging_error("critical", message, e)
    
    def operation(self, message: str, operation_name: str = "", data: Optional[Any] = None):
        """记录操作日志（专门用于记录用户操作和系统操作）"""
        try:
            # 获取调用者信息
            caller_info = self._get_caller_info(operation_name)
            
            # 构建完整日志消息
            full_message = f"【OPERATION】{caller_info} {message}"
            
            # 如果提供了数据，添加数据信息
            if data is not None:
                # 限制数据长度避免日志文件过大
                data_str = str(data)
                if len(data_str) > 1000:
                    data_str = data_str[:1000] + "...[数据被截断]"
                full_message += f" | 数据: {data_str}"
            
            # 写入操作日志
            if self.operation_logger:
                self.operation_logger.info(full_message)
                
            # 同时写入详细日志
            if self.detail_logger:
                self.detail_logger.info(full_message)
                
        except Exception as e:
            # 日志记录失败时的处理
            self._handle_logging_error("operation", message, e)
    
    def _handle_logging_error(self, level: str, message: str, error: Exception):
        """处理日志记录失败的情况"""
        try:
            # 构建错误信息
            error_msg = f"日志记录失败 - 级别:{level} 消息:{message} 错误:{error}"
            
            # 尝试写入系统标准错误输出
            sys.stderr.write(f"{datetime.now().isoformat()} {error_msg}\n")
            sys.stderr.flush()
            
        except Exception:
            # 如果连标准错误输出都失败，则忽略
            pass

# 全局日志实例（单例模式）
_server_logger = None
_client_logger = None
_logger_lock = threading.Lock()

def get_server_logger(clear_on_start: bool = False) -> SystemLogger:
    """获取服务端日志实例（单例模式）"""
    global _server_logger
    
    # 使用线程锁确保线程安全
    with _logger_lock:
        if _server_logger is None:
            _server_logger = SystemLogger('server', 'logs', clear_on_start)  # 创建服务端日志实例
        elif clear_on_start:
            # 如果需要清空且实例已存在，直接清空文件
            _server_logger._clear_log_files()
        return _server_logger

def get_client_logger(clear_on_start: bool = False) -> SystemLogger:
    """获取客户端日志实例（单例模式）"""
    global _client_logger
    
    # 使用线程锁确保线程安全  
    with _logger_lock:
        if _client_logger is None:
            _client_logger = SystemLogger('client', 'logs', clear_on_start)  # 创建客户端日志实例
        elif clear_on_start:
            # 如果需要清空且实例已存在，直接清空文件
            _client_logger._clear_log_files()
        return _client_logger

# 便捷的日志函数
def log_debug(message: str, operation_name: str = "", log_type: str = 'server'):
    """便捷的调试日志函数"""
    logger = get_server_logger() if log_type == 'server' else get_client_logger()
    logger.debug(message, operation_name)

def log_info(message: str, operation_name: str = "", log_type: str = 'server'):
    """便捷的信息日志函数"""
    logger = get_server_logger() if log_type == 'server' else get_client_logger()
    logger.info(message, operation_name)

def log_warning(message: str, operation_name: str = "", log_type: str = 'server'):
    """便捷的警告日志函数"""
    logger = get_server_logger() if log_type == 'server' else get_client_logger()
    logger.warning(message, operation_name)

def log_error(message: str, operation_name: str = "", exception: Optional[Exception] = None, log_type: str = 'server'):
    """便捷的错误日志函数"""
    logger = get_server_logger() if log_type == 'server' else get_client_logger()
    logger.error(message, operation_name, exception)

def log_critical(message: str, operation_name: str = "", exception: Optional[Exception] = None, log_type: str = 'server'):
    """便捷的关键错误日志函数"""
    logger = get_server_logger() if log_type == 'server' else get_client_logger()
    logger.critical(message, operation_name, exception)

def log_operation(message: str, operation_name: str = "", data: Optional[Any] = None, log_type: str = 'server'):
    """全局操作日志函数"""
    if log_type == 'server':
        get_server_logger().operation(message, operation_name, data)
    else:
        get_client_logger().operation(message, operation_name, data)

class EnhancedLogger:
    """增强型日志记录器，为特定实例提供日志功能"""
    
    def __init__(self, logger: SystemLogger, instance_id: str):
        """
        初始化增强型日志记录器
        
        Args:
            logger: 系统日志记录器
            instance_id: 实例ID
        """
        self.logger = logger
        self.instance_id = instance_id
        self.prefix = f"[{instance_id[:8]}] "  # 使用实例ID前8位作为前缀
    
    def debug(self, message: str, operation_name: str = ""):
        """记录调试级别日志"""
        self.logger.debug(f"{self.prefix}{message}", operation_name)
    
    def info(self, message: str, operation_name: str = ""):
        """记录信息级别日志"""
        self.logger.info(f"{self.prefix}{message}", operation_name)
    
    def warning(self, message: str, operation_name: str = ""):
        """记录警告级别日志"""
        self.logger.warning(f"{self.prefix}{message}", operation_name)
    
    def error(self, message: str, operation_name: str = "", exception: Optional[Exception] = None):
        """记录错误级别日志"""
        self.logger.error(f"{self.prefix}{message}", operation_name, exception)
    
    def critical(self, message: str, operation_name: str = "", exception: Optional[Exception] = None):
        """记录严重错误级别日志"""
        self.logger.critical(f"{self.prefix}{message}", operation_name, exception)
    
    def operation(self, message: str, operation_name: str = "", data: Optional[Any] = None):
        """记录操作日志"""
        # 添加实例ID到操作数据中
        if data is None:
            data = {}
        
        if isinstance(data, dict):
            data['instance_id'] = self.instance_id
        
        self.logger.operation(f"{self.prefix}{message}", operation_name, data) 