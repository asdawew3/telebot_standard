#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Telegram Bot服务器启动脚本
提供Web界面和API接口，支持多实例管理
"""

import os
import sys
import signal
from pathlib import Path

# 确保当前目录在Python路径中，以便导入server包
current_dir = Path(__file__).parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

# 记录Python路径调试信息（临时用于调试导入问题）
print(f"[DEBUG] 当前工作目录: {os.getcwd()}")
print(f"[DEBUG] 脚本所在目录: {current_dir}")
print(f"[DEBUG] Python路径已设置")

# 导入服务器模块
try:
    # 导入日志系统
    print("[DEBUG] 正在导入日志系统...")
    from server.logger import get_server_logger
    print("[DEBUG] 日志系统导入成功")
    
    # 导入配置管理
    print("[DEBUG] 正在导入配置管理...")
    from server.config import get_config
    print("[DEBUG] 配置管理导入成功")
    
    # 导入Flask应用
    print("[DEBUG] 正在导入Flask应用...")
    from server.app import run_server
    print("[DEBUG] Flask应用导入成功")
    
    # 导入网络管理器
    print("[DEBUG] 正在导入网络管理器...")
    from server.network_manager import get_network_manager
    print("[DEBUG] 网络管理器导入成功")
    
    print("[DEBUG] 所有服务器模块导入完成，正在初始化日志系统...")
    
    # 立即获取日志实例以便后续使用（启动时清空日志文件）
    logger = get_server_logger(clear_on_start=True)
    print("[DEBUG] 服务端日志系统初始化完成（已清空历史日志）")
    
    # 记录模块导入成功到日志文件
    logger.info("服务器模块导入完成", "main")
    logger.debug(f"当前工作目录: {os.getcwd()}", "main")
    logger.debug(f"脚本所在目录: {current_dir}", "main")
    logger.debug("Python包导入路径设置完成", "main")
    
except ImportError as e:
    print(f"[ERROR] 导入服务器模块失败: {e}")
    print("[ERROR] 请确保server目录下的所有模块文件都存在")
    print("[DEBUG] 当前目录结构:")
    
    # 显示当前目录结构用于调试
    try:
        for root, dirs, files in os.walk(current_dir):
            level = root.replace(str(current_dir), '').count(os.sep)
            indent = ' ' * 2 * level
            print(f"{indent}{os.path.basename(root)}/")
            subindent = ' ' * 2 * (level + 1)
            for file in files:
                if file.endswith('.py'):
                    print(f"{subindent}{file}")
    except Exception as debug_e:
        print(f"[ERROR] 显示目录结构失败: {debug_e}")
    
    sys.exit(1)

# 全局变量声明：logger实例在导入成功后已经初始化

def check_port_status(port):
    """检查端口状态"""
    logger.debug(f"检查端口 {port} 状态", "check_port_status")
    
    import socket
    
    try:
        # 尝试绑定端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            result = s.bind(('localhost', port))
            logger.info(f"端口 {port} 可用", "check_port_status")
            return True
            
    except socket.error as e:
        if e.errno == 10048:  # Windows: Address already in use
            logger.warning(f"端口 {port} 被占用 (Windows错误码: 10048)", "check_port_status")
        elif e.errno == 98:   # Linux: Address already in use
            logger.warning(f"端口 {port} 被占用 (Linux错误码: 98)", "check_port_status")
        else:
            logger.warning(f"端口 {port} 检查失败: {e}", "check_port_status")
        return False
    except Exception as e:
        logger.error(f"端口状态检查异常: {e}", "check_port_status", e)
        return False

def kill_port_processes(port):
    """终止占用指定端口的所有进程"""
    logger.info(f"检查并清理端口 {port} 上的进程", "kill_port_processes")
    
    # 方法1：使用psutil（推荐）
    try:
        import psutil
        logger.debug("使用psutil进行端口清理", "kill_port_processes")
        
        # 查找占用端口的进程
        killed_count = 0
        zombie_count = 0
        
        for proc in psutil.process_iter(['pid', 'name', 'connections', 'status']):
            try:
                # 检查进程状态
                if proc.info['status'] == psutil.STATUS_ZOMBIE:
                    zombie_count += 1
                    logger.debug(f"发现僵尸进程: PID={proc.info['pid']}, 名称={proc.info['name']}", "kill_port_processes")
                    continue
                
                # 检查进程的网络连接
                connections = proc.info['connections'] or []
                for conn in connections:
                    if hasattr(conn, 'laddr') and conn.laddr and conn.laddr.port == port:
                        logger.warning(f"发现占用端口 {port} 的进程: PID={proc.info['pid']}, 名称={proc.info['name']}, 状态={proc.info['status']}", "kill_port_processes")
                        
                        # 尝试优雅终止
                        try:
                            proc.terminate()
                            proc.wait(timeout=3)
                            killed_count += 1
                            logger.info(f"已优雅终止进程: PID={proc.info['pid']}", "kill_port_processes")
                        except psutil.TimeoutExpired:
                            # 强制终止
                            proc.kill()
                            killed_count += 1
                            logger.warning(f"强制终止进程: PID={proc.info['pid']}", "kill_port_processes")
                        except psutil.AccessDenied:
                            logger.warning(f"无权限终止进程: PID={proc.info['pid']}", "kill_port_processes")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # 忽略已经不存在或无法访问的进程
                continue
            except Exception as e:
                logger.debug(f"检查进程时发生异常: {e}", "kill_port_processes")
                continue
        
        if zombie_count > 0:
            logger.warning(f"检测到 {zombie_count} 个僵尸进程", "kill_port_processes")
        
        if killed_count > 0:
            logger.info(f"共终止了 {killed_count} 个占用端口 {port} 的进程", "kill_port_processes")
            # 等待系统释放端口
            import time
            time.sleep(3)
            logger.debug("等待端口释放完成", "kill_port_processes")
        else:
            logger.debug(f"未发现占用端口 {port} 的进程", "kill_port_processes")
            
        return True
        
    except ImportError:
        logger.warning("psutil模块未安装，使用备用方法进行端口清理", "kill_port_processes")
        return _kill_port_processes_fallback(port)
    except Exception as e:
        logger.error(f"使用psutil清理端口进程时发生异常: {e}", "kill_port_processes", e)
        return _kill_port_processes_fallback(port)

def _kill_port_processes_fallback(port):
    """备用端口清理方法（使用系统命令）"""
    logger.info(f"使用备用方法清理端口 {port}", "_kill_port_processes_fallback")
    
    import subprocess
    import platform
    
    try:
        system = platform.system().lower()
        
        if system == 'windows':
            # Windows系统使用netstat和taskkill
            logger.debug("使用Windows命令行工具清理端口", "_kill_port_processes_fallback")
            
            # 查找占用端口的进程ID
            try:
                result = subprocess.run([
                    'netstat', '-ano', '|', 'findstr', f':{port}'
                ], shell=True, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout:
                    lines = result.stdout.strip().split('\n')
                    pids = set()
                    
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 5 and f':{port}' in parts[1]:
                            pid = parts[-1]
                            if pid.isdigit():
                                pids.add(pid)
                                logger.debug(f"发现占用端口的进程ID: {pid}", "_kill_port_processes_fallback")
                    
                    # 终止进程
                    killed_count = 0
                    for pid in pids:
                        try:
                            subprocess.run(['taskkill', '/F', '/PID', pid], 
                                         check=True, capture_output=True, timeout=5)
                            killed_count += 1
                            logger.info(f"已终止进程: PID={pid}", "_kill_port_processes_fallback")
                        except subprocess.CalledProcessError as e:
                            logger.warning(f"终止进程失败: PID={pid}, 错误={e}", "_kill_port_processes_fallback")
                    
                    if killed_count > 0:
                        logger.info(f"备用方法共终止了 {killed_count} 个进程", "_kill_port_processes_fallback")
                        import time
                        time.sleep(2)
                    
                else:
                    logger.debug("未发现占用端口的进程", "_kill_port_processes_fallback")
                    
            except subprocess.TimeoutExpired:
                logger.warning("端口查询命令超时", "_kill_port_processes_fallback")
            except Exception as e:
                logger.warning(f"Windows端口清理失败: {e}", "_kill_port_processes_fallback")
                
        else:
            # Linux/Unix系统使用lsof和kill
            logger.debug("使用Unix命令行工具清理端口", "_kill_port_processes_fallback")
            
            try:
                result = subprocess.run([
                    'lsof', '-ti', f':{port}'
                ], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout:
                    pids = result.stdout.strip().split('\n')
                    killed_count = 0
                    
                    for pid in pids:
                        if pid.isdigit():
                            try:
                                subprocess.run(['kill', '-9', pid], check=True, timeout=5)
                                killed_count += 1
                                logger.info(f"已终止进程: PID={pid}", "_kill_port_processes_fallback")
                            except subprocess.CalledProcessError:
                                logger.warning(f"终止进程失败: PID={pid}", "_kill_port_processes_fallback")
                    
                    if killed_count > 0:
                        logger.info(f"备用方法共终止了 {killed_count} 个进程", "_kill_port_processes_fallback")
                        import time
                        time.sleep(2)
                else:
                    logger.debug("未发现占用端口的进程", "_kill_port_processes_fallback")
                    
            except subprocess.TimeoutExpired:
                logger.warning("端口查询命令超时", "_kill_port_processes_fallback")
            except Exception as e:
                logger.warning(f"Unix端口清理失败: {e}", "_kill_port_processes_fallback")
        
        return True
        
    except Exception as e:
        logger.error(f"备用端口清理方法失败: {e}", "_kill_port_processes_fallback", e)
        return False

def setup_signal_handlers():
    """设置信号处理器"""
    logger.info("设置信号处理器", "setup_signal_handlers")
    
    def signal_handler(signum, frame):
        """信号处理函数"""
        logger.info(f"收到信号: {signum}，开始优雅关闭服务器", "signal_handler")
        
        try:
            # 执行清理操作
            from server.instance_manager import instance_pool
            instance_pool.shutdown()
            logger.info("服务器优雅关闭完成", "signal_handler")
            
        except Exception as e:
            logger.error("服务器关闭过程发生异常", "signal_handler", e)
        
        finally:
            # 退出程序
            sys.exit(0)
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # 终止信号
    
    logger.info("信号处理器设置完成", "setup_signal_handlers")

def validate_environment():
    """验证运行环境"""
    logger.info("开始验证运行环境", "validate_environment")
    
    try:
        # 检查Python版本
        python_version = sys.version_info
        if python_version < (3, 8):
            logger.error(f"Python版本过低: {python_version}, 需要3.8或更高版本", "validate_environment")
            return False
        
        logger.debug(f"Python版本检查通过: {python_version}", "validate_environment")
        
        # 检查必要的目录
        required_dirs = ['logs', 'js_modules', 'profiles']
        for dir_name in required_dirs:
            dir_path = Path(dir_name)
            if not dir_path.exists():
                logger.info(f"创建必要目录: {dir_name}", "validate_environment")
                dir_path.mkdir(parents=True, exist_ok=True)
            else:
                logger.debug(f"目录已存在: {dir_name}", "validate_environment")
        
        # 检查JavaScript文件
        js_modules_path = Path('js_modules')
        if js_modules_path.exists():
            js_files = list(js_modules_path.glob('*.js'))
            logger.info(f"找到 js_modules 文件夹，包含 {len(js_files)} 个JavaScript文件", "validate_environment")
            for js_file in js_files:
                logger.debug(f"JavaScript文件: {js_file.name}", "validate_environment")
        else:
            logger.warning("js_modules 文件夹不存在", "validate_environment")
        
        # 检查配置文件中指定的JavaScript文件
        config = get_config()
        js_file_path = Path(config.js_file_path)
        if not js_file_path.exists():
            logger.warning(f"配置文件指定的JavaScript文件不存在: {js_file_path}", "validate_environment")
            logger.warning("某些功能可能无法正常工作", "validate_environment")
        else:
            logger.debug(f"配置文件指定的JavaScript文件检查通过: {js_file_path}", "validate_environment")
        
        logger.info("运行环境验证完成", "validate_environment")
        return True
        
    except Exception as e:
        logger.error("运行环境验证失败", "validate_environment", e)
        return False

def print_startup_banner():
    """打印启动横幅"""
    logger.info("显示启动横幅", "print_startup_banner")
    
    try:
        # 获取配置信息
        config = get_config()
        
        # 获取网络状态信息用于显示
        network_manager = get_network_manager()
        port_status = network_manager.check_port_accessibility(config.port)
        local_ip = port_status.get('local_ip', '未知')
        external_access = "已配置" if config.host == '0.0.0.0' else "仅本地"
        
        # 构建启动信息
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                    Telegram Bot Server v2.0                  ║
║                    基于Flask-Login认证系统                     ║
╠══════════════════════════════════════════════════════════════╣
║ 服务地址: http://{config.host}:{config.port:<15}                    ║
║ 本地地址: http://{local_ip}:{config.port:<15}                       ║
║ 外部访问: {external_access:<15}                               ║
║ 调试模式: {'开启' if config.debug else '关闭':<15}                         ║
║ 最大实例: {config.max_instances:<15}                              ║
║ 日志级别: {config.log_level:<15}                               ║
╚══════════════════════════════════════════════════════════════╝

[SUCCESS] 服务器启动成功！
[INFO] 本地访问: http://localhost:{config.port}/
[INFO] 局域网访问: http://{local_ip}:{config.port}/
[AUTH] 默认账户: 10086 / Kx7#mP9$nL2@wZ8!qR4%fH6^dG1&yU3*
[LOGS] 日志文件: logs/server_*.log
[NETWORK] 外部访问状态: {'已开启' if config.host == '0.0.0.0' else '仅本地访问'}

按 Ctrl+C 优雅关闭服务器
        """
        
        # 输出到控制台
        print(banner)
        
        # 记录到日志
        logger.info("服务器启动横幅显示完成", "print_startup_banner")
        
    except Exception as e:
        logger.error("显示启动横幅失败", "print_startup_banner", e)

def main():
    """主函数"""
    # 记录程序启动
    logger.info("="*60, "main")
    logger.info("Telegram Bot服务器启动", "main")
    logger.info("="*60, "main")
    
    try:
        # 获取配置以确定端口
        config = get_config()
        logger.info(f"服务器配置加载完成: 端口={config.port}, 主机={config.host}", "main")
        
        # 进行网络检查和配置
        logger.info("开始网络配置检查", "main")
        network_manager = get_network_manager()
        
        # 检查端口可访问性
        logger.debug(f"检查端口 {config.port} 的可访问性", "main")
        port_status = network_manager.check_port_accessibility(config.port)
        
        logger.info(f"端口状态检查结果 - 监听: {port_status.get('is_listening', False)}, "
                   f"可绑定: {port_status.get('can_bind', False)}, "
                   f"本地IP: {port_status.get('local_ip', '未知')}", "main")
        
        # 如果检查到网络配置问题，记录建议
        if port_status.get('suggestions'):
            logger.info("网络配置建议:", "main")
            for suggestion in port_status['suggestions']:
                logger.info(f"  - {suggestion}", "main")
        
        # 清理端口上的僵尸进程
        logger.info(f"开始清理端口 {config.port} 上的僵尸连接", "main")
        
        # 检查端口初始状态
        port_available_before = check_port_status(config.port)
        if not port_available_before:
            logger.warning(f"端口 {config.port} 被占用，尝试清理", "main")
            cleanup_success = kill_port_processes(config.port)
            
            if cleanup_success:
                # 再次检查端口状态
                port_available_after = check_port_status(config.port)
                if port_available_after:
                    logger.info(f"端口 {config.port} 清理成功，现在可用", "main")
                else:
                    logger.error(f"端口 {config.port} 清理后仍被占用，可能存在顽固进程", "main")
                    logger.warning("服务器可能无法正常启动，但尝试继续", "main")
            else:
                logger.warning(f"端口 {config.port} 清理可能不完整，但继续启动", "main")
        else:
            logger.info(f"端口 {config.port} 初始状态正常，无需清理", "main")
        
        # 验证运行环境
        logger.info("开始验证运行环境", "main")
        if not validate_environment():
            logger.error("运行环境验证失败，程序退出", "main")
            sys.exit(1)
        logger.info("运行环境验证通过", "main")
        
        # 设置信号处理器
        logger.info("设置信号处理器", "main")
        setup_signal_handlers()
        logger.info("信号处理器设置完成", "main")
        
        # 显示启动横幅
        logger.info("显示启动横幅", "main")
        print_startup_banner()
        
        # 启动服务器
        logger.info("准备启动Flask服务器", "main")
        logger.info(f"服务器将在 http://{config.host}:{config.port} 上启动", "main")
        run_server()
        
    except KeyboardInterrupt:
        logger.info("用户中断程序运行", "main")
    except Exception as e:
        logger.error("程序运行过程发生异常", "main", e)
        sys.exit(1)
    finally:
        logger.info("程序运行结束", "main")
        logger.info("="*60, "main")

if __name__ == '__main__':
    main() 