#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
客户端包初始化文件
提供客户端模块的导入支持
"""

import os
import sys
from pathlib import Path

# 确保当前目录在Python路径中
current_dir = Path(__file__).parent.parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

# 版本信息
__version__ = '1.0.0'

# 导出模块
from .client_logger import get_client_logger
from .client_web_app import run_client_web_app

# 初始化日志目录
log_dir = Path('logs')
if not log_dir.exists():
    try:
        log_dir.mkdir(exist_ok=True)
        print(f"[INFO] 创建日志目录: {log_dir}")
    except Exception as e:
        print(f"[WARNING] 无法创建日志目录: {e}") 