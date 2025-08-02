#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
服务器配置管理模块
集中管理服务器的各种配置参数
支持配置的动态加载和验证
"""

import os
import json
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

from .logger import get_server_logger

# 获取服务端日志实例
logger = get_server_logger()

@dataclass
class ServerConfig:
    """服务器配置数据类"""
    # 基本服务配置
    host: str = '0.0.0.0'                # 服务器监听地址（0.0.0.0允许外部访问）
    port: int = 5000                    # 服务器监听端口
    debug: bool = True                   # 是否开启调试模式
    start_time: float = 0.0             # 服务器启动时间
    
    # 实例管理配置
    max_instances: int = 10              # 最大实例数量
    instance_timeout: int = 3600         # 实例超时时间（秒）
    instance_cleanup_interval: int = 300 # 实例清理间隔（秒）
    
    # Telegram相关配置
    telegram_url: str = 'https://web.telegram.org/a/#6690063578'  # Telegram Web地址
    js_file_path: str = 'js_modules/console_test.js'              # JavaScript文件路径
    
    # 线程池配置
    thread_pool_size: int = 4            # 线程池大小
    
    # 浏览器配置
    headless: bool = False               # 是否无界面运行
    browser_timeout: int = 30            # 浏览器操作超时时间（秒）
    
    # 会话配置
    session_timeout: int = 10800         # 会话超时时间（3小时）
    secret_key: str = 'your-secret-key-here'  # Flask会话密钥
    
    # 日志配置
    log_level: str = 'DEBUG'             # 日志级别
    log_max_size: int = 50 * 1024 * 1024  # 日志文件最大大小（50MB）
    log_backup_count: int = 10           # 日志备份数量
    
    # 安全配置
    max_login_attempts: int = 5          # 最大登录尝试次数
    lockout_duration: int = 1800         # 锁定持续时间（30分钟）
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        logger.debug("配置对象转换为字典", "ServerConfig.to_dict")
        return asdict(self)

class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_file: str = 'config.json'):
        """
        初始化配置管理器
        
        Args:
            config_file: 配置文件路径
        """
        logger.info(f"初始化配置管理器，配置文件: {config_file}", "ConfigManager.__init__")
        
        # 设置配置文件路径
        self.config_file = config_file
        
        # 创建默认配置
        self.config = ServerConfig()
        
        # 设置服务器启动时间
        self.config.start_time = time.time()
        
        # 加载配置文件
        self.load_config()
        
        # 验证配置
        self.validate_config()
        
        logger.info("配置管理器初始化完成", "ConfigManager.__init__")
    
    def load_config(self):
        """加载配置文件"""
        logger.info(f"开始加载配置文件: {self.config_file}", "ConfigManager.load_config")
        
        try:
            # 检查配置文件是否存在
            if not os.path.exists(self.config_file):
                logger.warning(f"配置文件不存在，使用默认配置: {self.config_file}", "ConfigManager.load_config")
                
                # 保存默认配置到文件
                self.save_config()
                return
            
            # 读取配置文件
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            logger.debug(f"配置文件内容: {config_data}", "ConfigManager.load_config")
            
            # 更新配置对象
            for key, value in config_data.items():
                if hasattr(self.config, key):
                    logger.debug(f"更新配置项: {key} = {value}", "ConfigManager.load_config")
                    setattr(self.config, key, value)
                else:
                    logger.warning(f"未知配置项: {key}", "ConfigManager.load_config")
            
            logger.info("配置文件加载成功", "ConfigManager.load_config")
            
        except json.JSONDecodeError as e:
            logger.error(f"配置文件JSON解析失败: {self.config_file}", "ConfigManager.load_config", e)
            logger.warning("使用默认配置", "ConfigManager.load_config")
            
        except Exception as e:
            logger.error(f"加载配置文件失败: {self.config_file}", "ConfigManager.load_config", e)
            logger.warning("使用默认配置", "ConfigManager.load_config")
    
    def save_config(self):
        """保存配置到文件"""
        logger.info(f"保存配置到文件: {self.config_file}", "ConfigManager.save_config")
        
        try:
            # 获取配置字典
            config_data = self.config.to_dict()
            
            # 写入配置文件
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4, ensure_ascii=False)
            
            logger.info("配置文件保存成功", "ConfigManager.save_config")
            
        except Exception as e:
            logger.error(f"保存配置文件失败: {self.config_file}", "ConfigManager.save_config", e)
    
    def validate_config(self):
        """验证配置的有效性"""
        logger.info("开始验证配置", "ConfigManager.validate_config")
        
        try:
            # 验证端口号
            if not (1 <= self.config.port <= 65535):
                logger.error(f"端口号无效: {self.config.port}", "ConfigManager.validate_config")
                self.config.port = 5000
                logger.info(f"端口号重置为默认值: {self.config.port}", "ConfigManager.validate_config")
            
            # 验证监听地址
            if self.config.host not in ['127.0.0.1', '0.0.0.0', 'localhost']:
                logger.warning(f"监听地址可能无效: {self.config.host}，建议使用 0.0.0.0 或 127.0.0.1", "ConfigManager.validate_config")
            
            # 记录网络配置信息
            if self.config.host == '0.0.0.0':
                logger.info("服务器配置为对外开放访问（监听地址: 0.0.0.0）", "ConfigManager.validate_config")
            else:
                logger.info("服务器配置为仅本地访问（监听地址: 127.0.0.1）", "ConfigManager.validate_config")
            
            # 验证最大实例数
            if self.config.max_instances <= 0:
                logger.error(f"最大实例数无效: {self.config.max_instances}", "ConfigManager.validate_config")
                self.config.max_instances = 10
                logger.info(f"最大实例数重置为默认值: {self.config.max_instances}", "ConfigManager.validate_config")
            
            # 验证超时时间
            if self.config.instance_timeout <= 0:
                logger.error(f"实例超时时间无效: {self.config.instance_timeout}", "ConfigManager.validate_config")
                self.config.instance_timeout = 3600
                logger.info(f"实例超时时间重置为默认值: {self.config.instance_timeout}", "ConfigManager.validate_config")
            
            # 验证线程池大小
            if self.config.thread_pool_size <= 0:
                logger.error(f"线程池大小无效: {self.config.thread_pool_size}", "ConfigManager.validate_config")
                self.config.thread_pool_size = 4
                logger.info(f"线程池大小重置为默认值: {self.config.thread_pool_size}", "ConfigManager.validate_config")
            
            # 验证JavaScript文件路径
            if not os.path.exists(self.config.js_file_path):
                logger.warning(f"JavaScript文件不存在: {self.config.js_file_path}", "ConfigManager.validate_config")
            
            # 验证日志级别
            valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if self.config.log_level not in valid_log_levels:
                logger.error(f"日志级别无效: {self.config.log_level}", "ConfigManager.validate_config")
                self.config.log_level = 'DEBUG'
                logger.info(f"日志级别重置为默认值: {self.config.log_level}", "ConfigManager.validate_config")
            
            # 验证会话密钥
            if not self.config.secret_key or self.config.secret_key == 'your-secret-key-here':
                logger.warning("使用默认会话密钥，建议更改", "ConfigManager.validate_config")
                # 生成随机密钥
                import secrets
                self.config.secret_key = secrets.token_hex(32)
                logger.info("生成新的会话密钥", "ConfigManager.validate_config")
            
            logger.info("配置验证完成", "ConfigManager.validate_config")
            
        except Exception as e:
            logger.error("配置验证过程发生异常", "ConfigManager.validate_config", e)
    
    def get_config(self) -> ServerConfig:
        """获取配置对象"""
        logger.debug("获取配置对象", "ConfigManager.get_config")
        return self.config
    
    def update_config(self, **kwargs) -> bool:
        """更新配置"""
        logger.info(f"更新配置: {kwargs}", "ConfigManager.update_config")
        
        try:
            # 更新配置项
            updated = False
            for key, value in kwargs.items():
                if hasattr(self.config, key):
                    old_value = getattr(self.config, key)
                    setattr(self.config, key, value)
                    logger.debug(f"配置项更新: {key} = {old_value} -> {value}", "ConfigManager.update_config")
                    updated = True
                else:
                    logger.warning(f"未知配置项: {key}", "ConfigManager.update_config")
            
            if updated:
                # 验证更新后的配置
                self.validate_config()
                
                # 保存配置
                self.save_config()
                
                logger.info("配置更新成功", "ConfigManager.update_config")
                return True
            else:
                logger.warning("没有有效的配置项更新", "ConfigManager.update_config")
                return False
                
        except Exception as e:
            logger.error("更新配置过程发生异常", "ConfigManager.update_config", e)
            return False
    
    def get_config_dict(self) -> Dict[str, Any]:
        """获取配置字典"""
        logger.debug("获取配置字典", "ConfigManager.get_config_dict")
        return self.config.to_dict()

# 全局配置管理器实例
config_manager = ConfigManager()

def get_config() -> ServerConfig:
    """获取服务器配置（便捷函数）"""
    logger.debug("获取服务器配置", "get_config")
    return config_manager.get_config()

def update_server_config(**kwargs) -> bool:
    """更新服务器配置（便捷函数）"""
    logger.info(f"更新服务器配置: {kwargs}", "update_server_config")
    return config_manager.update_config(**kwargs) 