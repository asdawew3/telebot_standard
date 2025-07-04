#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import subprocess
import time
import threading
from typing import List, Optional, Dict, Any

# ================================
# 配置
# ================================

REQUIREMENTS_FILE = 'requirements.txt'
SERVER_SCRIPT = 'server.py'
CLIENT_SCRIPT = 'client_web.py'
SERVER_PORT = 5000
CLIENT_CONFIG_FILE = 'client_config.json'

# ================================
# 配置加载
# ================================

def load_client_config() -> Dict[str, Any]:
    """加载客户端配置"""
    try:
        if os.path.exists(CLIENT_CONFIG_FILE):
            print(f"加载客户端配置: {CLIENT_CONFIG_FILE}")
            with open(CLIENT_CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
            print("客户端配置加载成功")
            return config
        else:
            print(f"客户端配置文件不存在: {CLIENT_CONFIG_FILE}，使用默认值")
            return {}
    except Exception as e:
        print(f"加载客户端配置失败: {e}")
        return {}

# ================================
# 依赖检查和安装
# ================================

def check_python_version() -> bool:
    """检查Python版本"""
    if sys.version_info < (3, 8):
        print("错误: 需要Python 3.8或更高版本")
        return False
    return True

def check_file_exists(filename: str) -> bool:
    """检查文件是否存在"""
    if not os.path.exists(filename):
        print(f"错误: 文件不存在: {filename}")
        return False
    return True

def get_installed_packages() -> List[str]:
    """获取已安装的包列表"""
    try:
        result = subprocess.run([sys.executable, '-m', 'pip', 'list'], 
                              capture_output=True, text=True, check=True)
        installed = []
        for line in result.stdout.splitlines()[2:]:  # 跳过标题行
            if line.strip():
                package_name = line.split()[0].lower()
                installed.append(package_name)
        return installed
    except subprocess.CalledProcessError:
        return []

def check_dependencies() -> bool:
    """检查依赖是否已安装"""
    if not os.path.exists(REQUIREMENTS_FILE):
        print(f"错误: 依赖文件不存在: {REQUIREMENTS_FILE}")
        return False
    
    installed_packages = get_installed_packages()
    missing_packages = []
    
    with open(REQUIREMENTS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                package_name = line.split('==')[0].lower()
                if package_name not in installed_packages:
                    missing_packages.append(line)
    
    if missing_packages:
        print("缺少以下依赖包:")
        for package in missing_packages:
            print(f"  - {package}")
        return False
    
    return True

def install_dependencies() -> bool:
    """安装依赖"""
    print("正在安装依赖包...")
    try:
        subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', REQUIREMENTS_FILE
        ], check=True)
        print("依赖安装完成")
        return True
    except subprocess.CalledProcessError as e:
        print(f"依赖安装失败: {e}")
        return False

# ================================
# 进程管理
# ================================

class ProcessManager:
    """进程管理器"""
    
    def __init__(self, client_config: Dict[str, Any]):
        self.server_process: Optional[subprocess.Popen] = None
        self.client_process: Optional[subprocess.Popen] = None
        self.shutdown_event = threading.Event()
        self.client_config = client_config
        
        # 获取客户端配置的端口和主机
        self.client_port = self.client_config.get("port", 5001)
        self.client_host = self.client_config.get("host", "0.0.0.0")
    
    def start_server(self) -> bool:
        """启动服务端"""
        try:
            print("启动服务端...")
            self.server_process = subprocess.Popen([
                sys.executable, SERVER_SCRIPT
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
               text=True, bufsize=1, universal_newlines=True)
            
            # 启动输出监控线程
            threading.Thread(
                target=self._monitor_output, 
                args=(self.server_process, "服务端"),
                daemon=True
            ).start()
            
            # 等待服务端启动
            time.sleep(3)
            
            if self.server_process.poll() is None:
                print(f"服务端已启动 (PID: {self.server_process.pid})")
                return True
            else:
                print("服务端启动失败")
                return False
                
        except Exception as e:
            print(f"启动服务端失败: {e}")
            return False
    
    def start_client(self) -> bool:
        """启动客户端Web应用"""
        try:
            print("启动客户端Web应用...")
            
            # 使用从配置文件中读取的端口和主机
            print(f"使用配置: 端口={self.client_port}, 主机={self.client_host}")
            
            # 启动客户端Web应用，使用客户端脚本启动（会自动读取配置文件）
            self.client_process = subprocess.Popen([
                sys.executable, CLIENT_SCRIPT,
                '--host', self.client_host,
                '--port', str(self.client_port),
                '--server-url', f'http://127.0.0.1:{SERVER_PORT}'
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
               text=True, bufsize=1, universal_newlines=True)
            
            # 启动输出监控线程
            threading.Thread(
                target=self._monitor_output,
                args=(self.client_process, "客户端Web应用"),
                daemon=True
            ).start()
            
            # 等待客户端Web应用启动
            time.sleep(3)
            
            if self.client_process.poll() is None:
                print(f"客户端Web应用已启动 (PID: {self.client_process.pid})")
                return True
            else:
                print("客户端Web应用启动失败")
                return False
                
        except Exception as e:
            print(f"启动客户端Web应用失败: {e}")
            return False
    
    def _monitor_output(self, process: subprocess.Popen, name: str):
        """监控进程输出"""
        try:
            if process and process.stdout:
                for line in iter(process.stdout.readline, ''):
                    if line.strip():
                        print(f"[{name}] {line.rstrip()}")
                    if self.shutdown_event.is_set():
                        break
        except Exception:
            pass
    
    def stop_all(self):
        """停止所有进程"""
        self.shutdown_event.set()
        
        if self.client_process and self.client_process.poll() is None:
            print("停止客户端...")
            self.client_process.terminate()
            try:
                self.client_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.client_process.kill()
        
        if self.server_process and self.server_process.poll() is None:
            print("停止服务端...")
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
        
        print("所有进程已停止")
    
    def wait(self):
        """等待进程结束"""
        try:
            while True:
                if (self.server_process and self.server_process.poll() is not None) or \
                   (self.client_process and self.client_process.poll() is not None):
                    print("检测到进程异常退出")
                    break
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n收到中断信号，正在关闭...")

# ================================
# 主函数
# ================================

def print_banner():
    """打印启动横幅"""
    print("=" * 60)
    print("Telegram自动化系统启动器")
    print("=" * 60)

def print_urls(server_port, client_port):
    """打印访问地址"""
    print("\n" + "=" * 60)
    print("系统启动完成")
    print("=" * 60)
    print(f"服务端管理界面: http://localhost:{server_port}")
    print(f"客户端操作界面: http://localhost:{client_port}")
    print("=" * 60)
    print("\n按 Ctrl+C 退出系统")

def main():
    """主函数"""
    print_banner()
    
    # 检查Python版本
    if not check_python_version():
        sys.exit(1)
    
    # 检查必要文件
    required_files = [SERVER_SCRIPT]
    for filename in required_files:
        if not check_file_exists(filename):
            sys.exit(1)
    
    # 加载客户端配置
    client_config = load_client_config()
    client_port = client_config.get("port", 5001)
    
    # 检查客户端目录
    client_dir = 'client'
    if os.path.exists(client_dir) and os.path.isdir(client_dir):
        print(f"找到客户端目录: {client_dir}")
    else:
        print(f"错误: 客户端目录不存在: {client_dir}")
        sys.exit(1)
    
    # 检查JavaScript文件 - 优先检查js_modules文件夹
    js_folder = 'js_modules'
    if os.path.exists(js_folder) and os.path.isdir(js_folder):
        js_files = [f for f in os.listdir(js_folder) if f.endswith('.js')]
        if js_files:
            print(f"找到 js_modules 文件夹，包含 {len(js_files)} 个JavaScript文件")
        else:
            print("错误: js_modules 文件夹为空")
            sys.exit(1)
    else:
        # fallback到单文件模式
        if not check_file_exists('console_test.js'):
            print("错误: 请确保存在 js_modules 文件夹或 console_test.js 文件")
            sys.exit(1)
    
    # 检查和安装依赖
    if not check_dependencies():
        print("\n是否自动安装缺少的依赖包? (y/n): ", end="")
        if input().lower() in ['y', 'yes']:
            if not install_dependencies():
                sys.exit(1)
        else:
            print("请手动安装依赖包后重试")
            sys.exit(1)
    
    print("依赖检查通过")
    
    # 创建进程管理器
    manager = ProcessManager(client_config)
    
    try:
        # 启动服务端
        if not manager.start_server():
            print("服务端启动失败，退出")
            sys.exit(1)
        
        # 启动客户端
        if not manager.start_client():
            print("客户端启动失败，但服务端继续运行")
        
        print_urls(SERVER_PORT, client_port)
        
        # 等待用户中断或进程异常
        manager.wait()
        
    except KeyboardInterrupt:
        print("\n收到中断信号...")
    except Exception as e:
        print(f"系统运行异常: {e}")
    finally:
        manager.stop_all()

if __name__ == '__main__':
    main() 