#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
客户端Web应用启动脚本
提供独立启动客户端Web应用的功能
"""

import os
import sys
import argparse
from pathlib import Path

# 确保当前目录在Python路径中
current_dir = Path(__file__).parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='启动Telegram自动化系统客户端Web应用')
    parser.add_argument('--port', type=int, default=5001, help='客户端Web应用端口号')
    parser.add_argument('--server-url', type=str, default='http://127.0.0.1:5000', help='服务器地址')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='主机地址')
    args = parser.parse_args()
    
    try:
        # 导入客户端Web应用模块
        print(f"[INFO] 导入客户端Web应用模块...")
        from client.client_web_app import run_client_web_app
        
        # 启动客户端Web应用
        print(f"[INFO] 启动客户端Web应用: http://{args.host}:{args.port}")
        print(f"[INFO] 连接到服务器: {args.server_url}")
        run_client_web_app(port=args.port, server_url=args.server_url, host=args.host)
        
    except ImportError as e:
        print(f"[ERROR] 导入客户端模块失败: {e}")
        print("[ERROR] 请确保client目录存在且包含必要的模块")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] 启动客户端Web应用失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()