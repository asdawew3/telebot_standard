#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
服务端模块包初始化文件
导出主要的模块函数和类，使其可以被外部导入
"""

# 导入日志系统
from .logger import (
    get_server_logger,
    log_debug,
    log_info,
    log_warning,
    log_error,
    log_critical,
    log_operation
)

# 导入认证系统
from .auth import (
    auth_manager,
    user_loader,
    api_login_required,
    require_permission
)

# 导入配置管理
from .config import (
    get_config,
    ServerConfig,
    ConfigManager
)

# 导入实例管理
from .instance_manager import (
    instance_pool,
    TelegramInstance,
    InstancePool,
    InstanceStatus,
    InstanceMetadata
)

# 导入Flask应用
from .app import (
    create_app,
    run_server
)

# 版本信息
__version__ = "2.0.0"
__author__ = "TelegramBot System"
__description__ = "Telegram Bot 服务端模块包"

# 导出所有公共接口
__all__ = [
    # 日志系统
    'get_server_logger',
    'log_debug',
    'log_info',
    'log_warning',
    'log_error',
    'log_critical',
    'log_operation',
    
    # 认证系统
    'auth_manager',
    'user_loader',
    'api_login_required',
    'require_permission',
    
    # 配置管理
    'get_config',
    'ServerConfig',
    'ConfigManager',
    
    # 实例管理
    'instance_pool',
    'TelegramInstance',
    'InstancePool',
    'InstanceStatus',
    'InstanceMetadata',
    
    # Flask应用
    'create_app',
    'run_server',
    
    # 版本信息
    '__version__',
    '__author__',
    '__description__',
] 