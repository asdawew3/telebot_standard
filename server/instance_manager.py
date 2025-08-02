#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
实例管理器模块
负责创建、维护和销毁Telegram Bot实例
支持多实例并发运行，提供实例池管理
"""

import os
import sys
import time
import uuid
import json
import platform
import threading
import subprocess
import random
import shutil
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import WebDriverException, TimeoutException
from webdriver_manager.chrome import ChromeDriverManager

from .config import get_config
from .logger import get_server_logger, EnhancedLogger
from .network_manager import get_network_manager
from .chrome_network_fixer import get_chrome_network_fixer
from .chrome_devtools_manager import get_chrome_devtools_manager
from .js_manager import get_js_manager
from .profile_manager import get_profile_manager

# 获取日志实例
logger = get_server_logger()

# 创建增强日志记录器别名，保持与用户代码的兼容性
enhanced_logger = logger

class InstanceStatus:
    """实例状态常量"""
    CREATED = "created"         # 已创建
    INITIALIZING = "initializing"  # 初始化中
    READY = "ready"            # 就绪
    ERROR = "error"            # 错误
    TERMINATED = "terminated"   # 已终止

class InstanceError(Exception):
    """实例相关异常"""
    pass

class JSExecutionError(Exception):
    """JavaScript执行异常"""
    pass

@dataclass
class InstanceMetadata:
    """实例元数据"""
    id: str                     # 实例ID
    name: str                   # 实例名称
    status: str                 # 实例状态
    created_at: float           # 创建时间
    last_access: float          # 最后访问时间
    js_injected: bool           # JavaScript是否已注入
    connected_clients: List[str] # 连接的客户端列表
    group_id: str               # 所属分组ID
    profile_id: str             # 用户资料ID
    error_message: Optional[str] = None  # 错误信息
    devtools_enabled: bool = False  # 是否启用DevTools调试

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        logger.debug(f"实例元数据转换为字典: {self.id}", "InstanceMetadata.to_dict")
        
        # 转换为字典格式
        data = asdict(self)
        
        # 添加连接客户端数量
        data['connected_clients_count'] = len(data['connected_clients'])
        
        logger.debug(f"实例元数据字典: {self.id}, 连接客户端: {data['connected_clients_count']}", "InstanceMetadata.to_dict")
        
        return data

class TelegramInstance:
    """Telegram实例类"""
    
    def __init__(self, instance_id: str, name: str = None, group_id: str = 'default', profile_id: str = 'default'):
        """
        初始化Telegram实例
        
        Args:
            instance_id: 实例ID
            name: 实例名称
            group_id: 分组ID
            profile_id: 用户资料ID
        """
        # 获取日志实例
        global logger
        logger = get_server_logger()
        
        # 增强型日志记录器
        self.enhanced_logger = EnhancedLogger(logger, instance_id)
        enhanced_logger = self.enhanced_logger
        
        # 记录实例创建
        enhanced_logger.info(f"创建Telegram实例: {instance_id}", "__init__")
        enhanced_logger.debug(f"实例参数: name={name}, group_id={group_id}, profile_id={profile_id}", "__init__")
        
        # 基本属性
        self.id = instance_id
        self.instance_id = instance_id  # 兼容性别名
        
        # 调试相关属性
        self.debug_port = None  # 保存Chrome调试端口
        
        # 元数据
        self.metadata = InstanceMetadata(
            id=instance_id,
            name=name or f"实例_{instance_id[:8]}",
            status=InstanceStatus.CREATED,
            created_at=time.time(),
            last_access=time.time(),
            js_injected=False,
            connected_clients=[],
            group_id=group_id,
            profile_id=profile_id
        )
        enhanced_logger.debug(f"实例元数据初始化完成: {self.metadata.to_dict()}", "__init__")
        
        # 线程安全锁
        self._lock = threading.RLock()  # 可重入锁，防止死锁
        
        # 获取配置和管理器实例
        self.config = get_config()
        self.network_manager = get_network_manager()
        self.network_fixer = get_chrome_network_fixer()
        self.devtools_manager = get_chrome_devtools_manager()
        
        # 初始化浏览器相关属性
        self.driver = None  # WebDriver实例
        self.service = None  # Chrome服务实例
        
        logger.info(f"Telegram实例初始化完成: {instance_id}", "TelegramInstance.__init__")

    def _is_ubuntu_environment(self) -> bool:
        """检测是否为Ubuntu环境（使用Ubuntu管理器）"""
        try:
            # 直接检查操作系统类型
            enhanced_logger.debug("检测操作系统类型", "_is_ubuntu_environment")
            return platform.system().lower() == 'linux'
            
        except Exception as e:
            enhanced_logger.warning(f"操作系统检测失败: {e}", "_is_ubuntu_environment")
            return False

    def _find_system_chromedriver(self) -> Optional[str]:
        """查找系统中的ChromeDriver"""
        try:
            enhanced_logger.debug("开始查找系统ChromeDriver", "_find_system_chromedriver")
            
            # 常见的ChromeDriver路径
            possible_paths = [
                '/usr/bin/chromedriver',
                '/usr/local/bin/chromedriver',
                '/snap/bin/chromium.chromedriver',
                'chromedriver',  # PATH中的chromedriver
                'chromedriver.exe',  # Windows
            ]
            
            for path in possible_paths:
                enhanced_logger.debug(f"检查路径: {path}", "_find_system_chromedriver")
                
                # 使用shutil.which查找可执行文件
                found_path = shutil.which(path)
                if found_path:
                    enhanced_logger.debug(f"找到ChromeDriver: {found_path}", "_find_system_chromedriver")
                    
                    # 验证文件是否可执行
                    if os.access(found_path, os.X_OK):
                        enhanced_logger.info(f"系统ChromeDriver验证成功: {found_path}", "_find_system_chromedriver")
                        return found_path
                    else:
                        enhanced_logger.warning(f"ChromeDriver不可执行: {found_path}", "_find_system_chromedriver")
                
                # 直接检查文件是否存在
                if os.path.exists(path) and os.access(path, os.X_OK):
                    enhanced_logger.info(f"找到可执行的ChromeDriver: {path}", "_find_system_chromedriver")
                    return path
            
            enhanced_logger.debug("未找到系统ChromeDriver", "_find_system_chromedriver")
            return None
            
        except Exception as e:
            enhanced_logger.warning(f"查找系统ChromeDriver失败: {e}", "_find_system_chromedriver")
            return None

    def _validate_chromedriver_path(self, path: str) -> bool:
        """验证ChromeDriver路径是否有效"""
        try:
            enhanced_logger.debug(f"验证ChromeDriver路径: {path}", "_validate_chromedriver_path")
            
            # 检查文件是否存在
            if not os.path.exists(path):
                enhanced_logger.debug(f"ChromeDriver文件不存在: {path}", "_validate_chromedriver_path")
                return False
            
            # 检查文件是否可执行
            if not os.access(path, os.X_OK):
                enhanced_logger.debug(f"ChromeDriver文件不可执行: {path}", "_validate_chromedriver_path")
                return False
            
            # 尝试执行版本检查
            try:
                result = subprocess.run([path, '--version'], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                
                if result.returncode == 0:
                    version_info = result.stdout.strip()
                    enhanced_logger.debug(f"ChromeDriver版本信息: {version_info}", "_validate_chromedriver_path")
                    return True
                else:
                    enhanced_logger.debug(f"ChromeDriver版本检查失败: {result.stderr}", "_validate_chromedriver_path")
                    return False
                    
            except subprocess.TimeoutExpired:
                enhanced_logger.debug("ChromeDriver版本检查超时", "_validate_chromedriver_path")
                return False
            except Exception as e:
                enhanced_logger.debug(f"ChromeDriver版本检查异常: {e}", "_validate_chromedriver_path")
                return False
                
        except Exception as e:
            enhanced_logger.warning(f"ChromeDriver路径验证失败: {e}", "_validate_chromedriver_path")
            return False

    def _setup_profile_cache(self, options: Options):
        """设置用户资料缓存目录"""
        try:
            enhanced_logger.debug(f"开始设置用户资料缓存: {self.metadata.profile_id}", "_setup_profile_cache")
            
            # 确定用户资料目录路径
            profile_dir = os.path.abspath(os.path.join('profiles', self.metadata.profile_id))
            enhanced_logger.debug(f"用户资料目录路径: {profile_dir}", "_setup_profile_cache")
            
            # 创建用户资料目录
            os.makedirs(profile_dir, exist_ok=True)
            enhanced_logger.debug(f"用户资料目录创建成功: {profile_dir}", "_setup_profile_cache")
            
            # 设置用户数据目录
            options.add_argument(f'--user-data-dir={profile_dir}')
            enhanced_logger.debug(f"用户数据目录设置完成: {profile_dir}", "_setup_profile_cache")
            
            # 设置缓存目录
            cache_dir = os.path.join(profile_dir, 'cache')
            os.makedirs(cache_dir, exist_ok=True)
            options.add_argument(f'--disk-cache-dir={cache_dir}')
            enhanced_logger.debug(f"缓存目录设置完成: {cache_dir}", "_setup_profile_cache")
            
            enhanced_logger.info(f"用户资料缓存配置完成: {self.metadata.profile_id}", "_setup_profile_cache")
            
        except Exception as e:
            enhanced_logger.error(f"用户资料缓存设置失败: {e}", "_setup_profile_cache", e)
            raise

    def _verify_image_loading(self):
        """验证图片加载设置是否正确"""
        try:
            enhanced_logger.debug("开始验证图片加载设置", "_verify_image_loading")
            
            # 检查Chrome设置中的图片加载状态 - 使用更安全的JavaScript
            image_settings_script = """
                try {
                    // 安全的图片加载设置检查脚本
                    var result = {
                        imagesEnabled: true,
                        imageCount: 0,
                        cspHeaders: [],
                        userAgent: '',
                        cookiesEnabled: false,
                        brokenImages: 0,
                        documentReady: false
                    };
                    
                    // 安全检查navigator对象
                    if (typeof navigator !== 'undefined' && navigator) {
                        try {
                            result.userAgent = navigator.userAgent || '';
                            result.cookiesEnabled = navigator.cookieEnabled || false;
                        } catch (e) {
                            console.warn('获取navigator信息失败:', e.message);
                        }
                    }
                    
                    // 安全检查document对象
                    if (typeof document !== 'undefined' && document) {
                        try {
                            result.documentReady = (document.readyState === 'complete' || document.readyState === 'interactive');
                            
                            // 安全获取图片数量
                            if (document.images && document.images.length !== undefined) {
                                result.imageCount = document.images.length;
                            }
                            
                            // 安全检查CSP头部
                            if (document.querySelectorAll) {
                                var metaTags = document.querySelectorAll('meta[http-equiv]');
                                if (metaTags && metaTags.forEach) {
                                    metaTags.forEach(function(meta) {
                                        try {
                                            if (meta && meta.httpEquiv && meta.content) {
                                                var httpEquiv = meta.httpEquiv.toLowerCase();
                                                if (httpEquiv.includes('content-security-policy')) {
                                                    result.cspHeaders.push(meta.content);
                                                }
                                            }
                                        } catch (e) {
                                            console.warn('检查CSP头部失败:', e.message);
                                        }
                                    });
                                }
                            }
                            
                            // 安全检查损坏的图片
                            if (document.querySelectorAll) {
                                var images = document.querySelectorAll('img');
                                if (images && images.forEach) {
                                    var brokenCount = 0;
                                    images.forEach(function(img) {
                                        try {
                                            if (img && typeof img.naturalWidth === 'number' && typeof img.naturalHeight === 'number') {
                                                if (img.naturalWidth === 0 && img.naturalHeight === 0 && img.src) {
                                                    brokenCount++;
                                                }
                                            }
                                        } catch (e) {
                                            console.warn('检查图片状态失败:', e.message);
                                        }
                                    });
                                    result.brokenImages = brokenCount;
                                }
                            }
                        } catch (e) {
                            console.warn('文档检查失败:', e.message);
                        }
                    }
                    
                    return result;
                } catch (e) {
                    console.error('图片加载检查脚本执行失败:', e.message);
                    return {
                        imagesEnabled: true,
                        imageCount: 0,
                        cspHeaders: [],
                        userAgent: '',
                        cookiesEnabled: false,
                        brokenImages: 0,
                        documentReady: false,
                        error: e.message
                    };
                }
            """
            
            # 执行检查脚本 - 增加异常处理
            try:
                result = self.driver.execute_script(image_settings_script)
                enhanced_logger.info(f"图片加载验证结果: {result}", "_verify_image_loading")
                
                # 检查脚本执行结果
                if result and isinstance(result, dict):
                    enhanced_logger.debug(f"页面图片总数: {result.get('imageCount', 0)}", "_verify_image_loading")
                    enhanced_logger.debug(f"损坏图片数量: {result.get('brokenImages', 0)}", "_verify_image_loading")
                    enhanced_logger.debug(f"Cookie启用状态: {result.get('cookiesEnabled', False)}", "_verify_image_loading")
                    enhanced_logger.debug(f"文档就绪状态: {result.get('documentReady', False)}", "_verify_image_loading")
                    
                    # 检查是否有脚本执行错误
                    if 'error' in result:
                        enhanced_logger.warning(f"图片检查脚本报告错误: {result['error']}", "_verify_image_loading")
                    
                    # 检查CSP头部
                    csp_headers = result.get('cspHeaders', [])
                    if csp_headers:
                        enhanced_logger.warning(f"检测到CSP头部，可能影响图片加载: {csp_headers}", "_verify_image_loading")
                    else:
                        enhanced_logger.debug("未检测到CSP头部限制", "_verify_image_loading")
                    
                    # 强制刷新页面图片（如果需要且文档已就绪）
                    broken_images = result.get('brokenImages', 0)
                    if broken_images > 0 and result.get('documentReady', False):
                        enhanced_logger.warning(f"检测到 {broken_images} 个损坏图片，尝试强制刷新", "_verify_image_loading")
                        
                        # 安全的图片刷新脚本
                        refresh_script = """
                            try {
                                if (typeof document !== 'undefined' && document && document.querySelectorAll) {
                                    var images = document.querySelectorAll('img');
                                    if (images && images.forEach) {
                                        var refreshCount = 0;
                                        images.forEach(function(img) {
                                            try {
                                                if (img && img.src && typeof img.naturalWidth === 'number' && typeof img.naturalHeight === 'number') {
                                                    if (img.naturalWidth === 0 && img.naturalHeight === 0) {
                                                        var originalSrc = img.src;
                                                        img.src = '';
                                                        setTimeout(function() {
                                                            img.src = originalSrc;
                                                        }, 10);
                                                        refreshCount++;
                                                    }
                                                }
                                            } catch (e) {
                                                console.warn('刷新单个图片失败:', e.message);
                                            }
                                        });
                                        console.log('尝试刷新图片数量:', refreshCount);
                                    }
                                }
                            } catch (e) {
                                console.warn('图片刷新脚本执行失败:', e.message);
                            }
                        """
                        
                        try:
                            self.driver.execute_script(refresh_script)
                            enhanced_logger.debug("图片强制刷新脚本执行完成", "_verify_image_loading")
                        except Exception as refresh_error:
                            enhanced_logger.warning(f"图片强制刷新失败: {refresh_error}", "_verify_image_loading")
                    
                else:
                    enhanced_logger.warning("图片验证脚本返回无效结果", "_verify_image_loading")
                    
            except Exception as script_error:
                enhanced_logger.warning(f"图片验证脚本执行失败: {script_error}", "_verify_image_loading")
            
            enhanced_logger.info("图片加载设置验证完成", "_verify_image_loading")
            
        except Exception as e:
            enhanced_logger.warning(f"图片加载验证过程失败，但不影响正常使用: {e}", "_verify_image_loading")

    def initialize_browser(self) -> bool:
        """初始化浏览器"""
        with self._lock:
            try:
                # 详细记录实例状态
                enhanced_logger.debug(f"进入initialize_browser方法: instance_id={self.instance_id}", "initialize_browser")
                enhanced_logger.debug(f"实例属性检查: id={self.id}, metadata.id={self.metadata.id}", "initialize_browser")
                enhanced_logger.debug(f"用户资料ID检查: metadata.profile_id={self.metadata.profile_id}", "initialize_browser")
                enhanced_logger.debug(f"分组ID检查: metadata.group_id={self.metadata.group_id}", "initialize_browser")
                
                enhanced_logger.info(f"开始初始化浏览器: {self.id} (资料: {self.metadata.profile_id})", "initialize_browser")
                self.metadata.status = InstanceStatus.INITIALIZING
                enhanced_logger.debug(f"实例状态更新为: {self.metadata.status}", "initialize_browser")
                
                # 配置Chrome选项
                options = Options()
                
                # 使用用户资料配置缓存目录
                try:
                    self._setup_profile_cache(options)
                    enhanced_logger.info(f"用户资料缓存配置成功: {self.metadata.profile_id}", "initialize_browser")
                except Exception as e:
                    enhanced_logger.warning(f"用户资料缓存配置失败，继续使用默认模式: {e}", "initialize_browser")
                
                # 基础必需选项（解决启动崩溃的核心参数）
                options.add_argument('--no-sandbox')                    # 禁用沙盒模式（重要：解决权限问题）
                options.add_argument('--disable-dev-shm-usage')         # 禁用/dev/shm使用（重要：解决内存问题）
                options.add_argument('--disable-gpu')                   # 禁用GPU加速
                options.add_argument('--disable-gpu-sandbox')           # 禁用GPU沙盒
                options.add_argument('--disable-software-rasterizer')   # 禁用软件光栅化
                options.add_argument('--disable-background-timer-throttling')  # 禁用后台定时器节流
                options.add_argument('--disable-backgrounding-occluded-windows')  # 禁用被遮挡窗口的后台处理
                options.add_argument('--disable-renderer-backgrounding')  # 禁用渲染器后台处理
                options.add_argument('--disable-features=TranslateUI')  # 禁用翻译UI
                options.add_argument('--disable-features=VizDisplayCompositor')  # 禁用显示合成器
                options.add_argument('--disable-ipc-flooding-protection')  # 禁用IPC洪水保护
                
                # JavaScript执行环境优化选项（重要：解决"Illegal invocation"错误）
                options.add_argument('--disable-blink-features=AutomationControlled')  # 禁用自动化控制检测
                options.add_argument('--disable-features=VizDisplayCompositor')       # 禁用可视化显示合成器
                options.add_argument('--disable-features=VizFrameSubmissionForWebView')  # 禁用WebView框架提交
                options.add_argument('--disable-background-timer-throttling')          # 禁用后台定时器节流
                options.add_argument('--disable-renderer-backgrounding')               # 禁用渲染器后台处理
                options.add_argument('--disable-field-trial-config')                  # 禁用字段试验配置
                options.add_argument('--disable-back-forward-cache')                  # 禁用前后缓存
                options.add_argument('--disable-backgrounding-occluded-windows')      # 禁用被遮挡窗口后台处理
                options.add_argument('--disable-features=Translate')                  # 禁用翻译功能
                enhanced_logger.debug("JavaScript执行环境优化选项已配置", "initialize_browser")
                
                # 安全和权限选项（避免权限相关的JavaScript错误）
                options.add_argument('--disable-web-security')          # 禁用Web安全
                options.add_argument('--ignore-certificate-errors')     # 忽略证书错误
                options.add_argument('--ignore-ssl-errors')             # 忽略SSL错误
                options.add_argument('--ignore-certificate-errors-spki-list')  # 忽略证书错误列表
                options.add_argument('--ignore-certificate-errors-ssl-errors')  # 忽略SSL证书错误
                options.add_argument('--allow-running-insecure-content') # 允许运行不安全内容
                options.add_argument('--disable-features=VizDisplayCompositor')  # 禁用显示合成器
                options.add_argument('--disable-site-isolation-trials') # 禁用站点隔离试验
                options.add_argument('--disable-features=BlockInsecurePrivateNetworkRequests') # 禁用阻止不安全私有网络请求
                enhanced_logger.debug("网络连接选项已配置", "initialize_browser")
                
                # 图片和媒体加载选项（解决图片拦截问题）
                options.add_argument('--allow-images')                  # 明确允许图片加载
                options.add_argument('--disable-image-animation-resync') # 禁用图片动画重同步
                options.add_argument('--enable-features=NetworkService') # 启用网络服务
                options.add_argument('--disable-features=BlockInsecurePrivateNetworkRequests') # 禁用阻止不安全私有网络请求
                enhanced_logger.debug("添加图片和媒体加载优化选项", "initialize_browser")
                enhanced_logger.info("已应用图片拦截修复方案 - 包含多层保护机制", "initialize_browser")
                
                # 基本功能选项
                options.add_argument('--disable-extensions')            # 禁用扩展
                options.add_argument('--disable-plugins')               # 禁用插件
                options.add_argument('--disable-default-apps')          # 禁用默认应用
                options.add_argument('--no-first-run')                  # 跳过首次运行设置
                options.add_argument('--no-default-browser-check')      # 跳过默认浏览器检查
                options.add_argument('--disable-default-browser-check') # 禁用默认浏览器检查
                options.add_argument('--disable-sync')                  # 禁用同步
                options.add_argument('--disable-translate')             # 禁用翻译
                
                # 启用远程调试功能
                enhanced_logger.info("启用Chrome远程调试功能", "initialize_browser")
                # 使用固定端口范围，便于后续连接
                debug_port = random.randint(9222, 9299)  # 使用9222-9299范围的端口
                options.add_argument(f'--remote-debugging-port={debug_port}')
                # 允许任何源连接到DevTools，解决WebSocket连接被拒绝的问题
                options.add_argument('--remote-allow-origins=*')
                enhanced_logger.debug(f"配置远程调试端口: {debug_port}，允许所有源连接", "initialize_browser")
                
                # 保存调试端口到实例属性中
                self.debug_port = debug_port
                enhanced_logger.debug(f"保存调试端口到实例属性: {self.debug_port}", "initialize_browser")
                
                # 性能优化和稳定性选项
                options.add_argument('--disable-notifications')         # 禁用通知
                options.add_argument('--disable-popup-blocking')        # 禁用弹窗阻止
                options.add_argument('--disable-background-mode')       # 禁用后台模式
                options.add_argument('--disable-hang-monitor')          # 禁用挂起监视器
                options.add_argument('--disable-prompt-on-repost')      # 禁用重新提交提示
                options.add_argument('--disable-domain-reliability')    # 禁用域名可靠性
                options.add_argument('--disable-component-extensions-with-background-pages')  # 禁用后台页面组件扩展
                
                # 媒体处理选项
                options.add_argument('--use-fake-ui-for-media-stream')  # 使用虚假媒体流UI
                options.add_argument('--autoplay-policy=no-user-gesture-required')  # 自动播放策略
                options.add_argument('--disable-background-media-suspend')  # 禁用后台媒体挂起
                options.add_argument('--disable-media-session-api')     # 禁用媒体会话API
                
                # 日志和调试选项（减少输出）
                options.add_argument('--log-level=3')                   # 设置日志级别（只显示致命错误）
                options.add_argument('--silent')                        # 静默模式
                options.add_argument('--disable-logging')               # 禁用日志
                options.add_argument('--disable-dev-tools')             # 禁用开发者工具
                options.add_argument('--disable-infobars')              # 禁用信息栏
                
                # 崩溃报告和错误处理
                options.add_argument('--disable-crash-reporter')        # 禁用崩溃报告
                options.add_argument('--disable-in-process-stack-traces')  # 禁用进程内堆栈跟踪
                options.add_argument('--disable-logging-redirect')      # 禁用日志重定向
                
                # Windows特定的稳定性选项
                if platform.system().lower() == 'windows':
                    options.add_argument('--disable-win32k-lockdown')   # 禁用Win32k锁定
                    options.add_argument('--disable-features=RendererCodeIntegrity')  # 禁用渲染器代码完整性
                    enhanced_logger.debug("添加Windows特定稳定性选项", "initialize_browser")
                
                # 窗口设置
                options.add_argument('--window-size=1920,1080')
                
                # 智能判断是否使用headless模式
                config_headless = self.config.headless
                ubuntu_headless = self.config.headless
                is_headless = config_headless or ubuntu_headless
                
                if is_headless:
                    options.add_argument('--headless=new')  # 使用新的headless模式
                    enhanced_logger.info(f"启用headless模式 (配置强制: {config_headless}, Ubuntu环境要求: {ubuntu_headless})", 
                                       "initialize_browser")
                else:
                    enhanced_logger.info(f"启用GUI模式 (配置: {config_headless}, Ubuntu环境: {ubuntu_headless})", 
                                       "initialize_browser")
                
                # 如果是Ubuntu环境，应用Ubuntu特定的优化
                if self._is_ubuntu_environment():
                    enhanced_logger.info("检测到Ubuntu环境，应用Ubuntu特定优化", "initialize_browser")
                    
                    # Ubuntu特定的稳定性选项
                    ubuntu_options = [
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--no-sandbox',
                        '--disable-setuid-sandbox'
                    ]
                    
                    for opt in ubuntu_options:
                        options.add_argument(opt)
                        enhanced_logger.debug(f"添加Ubuntu特定选项: {opt}", "initialize_browser")
                    
                    enhanced_logger.info(f"Ubuntu优化完成，添加了 {len(ubuntu_options)} 个特定选项", "initialize_browser")
                
                # 网络连接管理器优化（解决Chrome无法连网的问题）
                enhanced_logger.info("开始应用Chrome网络连接优化配置", "initialize_browser")
                
                # 记录网络优化开始
                self.network_manager.log_network_event(
                    level='INFO',
                    category='OPTIMIZATION',
                    message="应用网络连接优化",
                    instance_id=self.instance_id
                )
                
                try:
                    # 获取网络优化配置
                    enhanced_logger.debug("获取网络优化配置", "initialize_browser")
                    network_options = self.network_manager.get_chrome_network_options()
                    
                    # 应用网络选项
                    enhanced_logger.debug(f"应用网络选项: {len(network_options)} 个", "initialize_browser")
                    for option in network_options:
                        options.add_argument(option)
                        enhanced_logger.debug(f"添加网络选项: {option}", "initialize_browser")
                        self.network_manager.log_chrome_option(self.instance_id, option, "网络优化")
                    
                    enhanced_logger.info(f"Chrome网络连接优化配置完成: 总计添加 {len(network_options)} 个选项", "initialize_browser")
                    
                except Exception as network_error:
                    enhanced_logger.warning(f"网络优化配置失败，使用默认配置: {network_error}", "initialize_browser")
                    
                    # 记录网络优化失败
                    self.network_manager.log_network_event(
                        level='WARNING',
                        category='OPTIMIZATION',
                        message=f'网络优化配置失败，启动网络修复器: {str(network_error)}',
                        instance_id=self.instance_id,
                        error=str(network_error)
                    )
                    
                    # 使用网络修复器生成修复选项
                    try:
                        enhanced_logger.info("启动Chrome网络修复器", "initialize_browser")
                        fix_result = self.network_fixer.diagnose_and_fix(self.instance_id)
                        
                        # 应用修复选项
                        for fix_option in fix_result['chrome_options']:
                            options.add_argument(fix_option)
                            enhanced_logger.debug(f"添加网络修复选项: {fix_option}", "initialize_browser")
                            self.network_manager.log_chrome_option(self.instance_id, fix_option, "网络修复")
                        
                        enhanced_logger.info(f"网络修复器应用完成: {len(fix_result['chrome_options'])} 个选项", "initialize_browser")
                        
                    except Exception as fix_error:
                        enhanced_logger.error(f"网络修复器也失败，使用最基础选项: {fix_error}", "initialize_browser")
                        
                        # 最后的兜底选项
                        fallback_options = [
                            '--no-sandbox',
                            '--disable-web-security',
                            '--ignore-certificate-errors'
                        ]
                        
                        for fallback_option in fallback_options:
                            options.add_argument(fallback_option)
                            enhanced_logger.debug(f"添加兜底网络选项: {fallback_option}", "initialize_browser")
                            self.network_manager.log_chrome_option(self.instance_id, fallback_option, "兜底修复")
                        
                        enhanced_logger.info(f"兜底网络配置应用完成: {len(fallback_options)} 个选项", "initialize_browser")
                
                # 反检测选项
                options.add_experimental_option('excludeSwitches', ['enable-automation'])
                options.add_experimental_option('useAutomationExtension', False)
                
                # 设置Chrome偏好（优化浏览体验和稳定性）
                prefs = {
                    'profile.default_content_setting_values': {
                        'notifications': 2,          # 禁用通知
                        'media_stream': 2,           # 禁用媒体流
                        'geolocation': 2,            # 禁用地理位置
                        'plugins': 2,                # 禁用插件
                        'popups': 2,                 # 禁用弹窗
                        'automatic_downloads': 2,    # 禁用自动下载
                        'images': 1,                 # 允许图片加载（重要：解决图片拦截问题）
                    },
                    'profile.managed_default_content_settings': {
                        'images': 1,                 # 允许图片加载（确保图片不被拦截）
                    },
                    'profile.default_content_settings': {
                        'popups': 0,                 # 允许弹窗（某些情况需要）
                        'images': 1,                 # 允许图片加载（三重保险）
                    },
                    # 禁用各种服务和功能
                    'profile.password_manager_enabled': False,  # 禁用密码管理器
                    'credentials_enable_service': False,        # 禁用凭据服务
                    'profile.default_content_setting_values.notifications': 2,  # 禁用通知
                    'autofill.profile_enabled': False,          # 禁用自动填充
                    'autofill.credit_card_enabled': False,      # 禁用信用卡自动填充
                    'translate.enabled': False,                 # 禁用翻译
                    'safebrowsing.enabled': False,              # 禁用安全浏览（避免拦截内容）
                    'search.suggest_enabled': False,            # 禁用搜索建议
                    'alternate_error_pages.enabled': False,     # 禁用备用错误页面
                    'spellcheck.dictionary': '',                # 禁用拼写检查
                    'spellcheck.use_spelling_service': False,   # 禁用拼写服务
                    # 图片和媒体相关设置
                    'profile.content_settings.exceptions.images': {},  # 清除图片例外设置
                    'profile.content_settings.pattern_pairs.images': {},  # 清除图片模式设置
                    # 安全和隐私设置（避免内容拦截）
                    'profile.block_third_party_cookies': False,        # 允许第三方Cookie
                    'profile.cookie_controls_mode': 0,                 # 允许所有Cookie
                    'profile.managed_default_content_settings.images': 1,  # 管理设置中允许图片
                    'webkit.webprefs.images_enabled': True,            # WebKit图片启用
                    'webkit.webprefs.loads_images_automatically': True, # WebKit自动加载图片
                    # 内容过滤设置
                    'profile.default_content_setting_values.mixed_script': 1,  # 允许混合脚本
                    'profile.default_content_setting_values.protocol_handlers': 1,  # 允许协议处理器
                }
                options.add_experimental_option('prefs', prefs)
                enhanced_logger.debug("Chrome偏好设置配置完成", "initialize_browser")
                enhanced_logger.info("图片加载设置已优化 - 禁用所有图片拦截机制", "initialize_browser")
                enhanced_logger.debug(f"图片加载相关设置: images=1, safebrowsing=False, web_security=disabled", "initialize_browser")
                
                # ChromeDriver管理 - 优化的跨平台初始化策略
                service = None
                system = platform.system().lower()
                
                try:
                    # Windows环境优先使用webdriver-manager自动管理
                    if system == 'windows':
                        enhanced_logger.info(f"Windows环境使用webdriver-manager自动管理ChromeDriver", 
                                           "initialize_browser")
                        try:
                            wdm_path = ChromeDriverManager().install()
                            if self._validate_chromedriver_path(wdm_path):
                                enhanced_logger.info(f"webdriver-manager成功获取ChromeDriver: {wdm_path}", 
                                                   "initialize_browser")
                                service = Service(wdm_path)
                            else:
                                enhanced_logger.warning(f"webdriver-manager返回无效文件: {wdm_path}", 
                                                       "initialize_browser")
                        except Exception as wdm_error:
                            enhanced_logger.warning(f"webdriver-manager失败，尝试系统ChromeDriver: {wdm_error}", 
                                                   "initialize_browser")
                    
                    # Linux环境优先查找系统ChromeDriver
                    if not service:
                        system_chromedriver = self._find_system_chromedriver()
                        if system_chromedriver:
                            enhanced_logger.info(f"找到并使用系统ChromeDriver: {system_chromedriver} (系统: {system})", 
                                               "initialize_browser")
                            service = Service(system_chromedriver)
                    
                    # 备用方案：尝试webdriver-manager（Linux环境）
                    if not service and system != 'windows':
                        try:
                            enhanced_logger.info(f"尝试webdriver-manager自动管理ChromeDriver (系统: {system})", 
                                                "initialize_browser")
                            wdm_path = ChromeDriverManager().install()
                            
                            # 验证webdriver-manager返回的路径
                            if self._validate_chromedriver_path(wdm_path):
                                enhanced_logger.info(f"webdriver-manager成功获取ChromeDriver: {wdm_path}", 
                                                    "initialize_browser")
                                service = Service(wdm_path)
                            else:
                                enhanced_logger.warning(f"webdriver-manager返回无效文件: {wdm_path}", 
                                                       "initialize_browser")
                                
                        except Exception as wdm_error:
                            enhanced_logger.warning(f"webdriver-manager失败: {wdm_error}", 
                                                   "initialize_browser")
                    
                    # 如果仍然没有找到service，生成详细的错误信息
                    if not service:
                        error_msgs = []
                        
                        if system == 'linux':
                            error_msgs.append("Ubuntu/Linux环境下建议安装系统ChromeDriver:")
                            error_msgs.append("  sudo apt update")
                            error_msgs.append("  sudo apt install chromium-chromedriver")
                            error_msgs.append("或者:")
                            error_msgs.append("  sudo apt install google-chrome-stable")
                            error_msgs.append("  wget -O /tmp/chromedriver.zip https://chromedriver.storage.googleapis.com/LATEST_RELEASE/chromedriver_linux64.zip")
                            error_msgs.append("  sudo unzip /tmp/chromedriver.zip -d /usr/local/bin/")
                            error_msgs.append("  sudo chmod +x /usr/local/bin/chromedriver")
                        else:
                            error_msgs.append("Windows环境下请:")
                            error_msgs.append("1. 下载ChromeDriver: https://chromedriver.chromium.org/")
                            error_msgs.append("2. 将chromedriver.exe放在项目目录或PATH中")
                            error_msgs.append("3. 确保Chrome浏览器已安装")
                        
                        error_message = "无法找到可用的ChromeDriver。\n" + "\n".join(error_msgs)
                        raise InstanceError(error_message)
                                
                except Exception as e:
                    enhanced_logger.error(f"ChromeDriver初始化失败 (系统: {system}): {e}", 
                                         "initialize_browser", e)
                    raise InstanceError(f"无法初始化ChromeDriver: {e}")
                
                # 启动Chrome浏览器
                enhanced_logger.info(f"正在启动Chrome浏览器 (实例: {self.id}, 资料: {self.metadata.profile_id})", "initialize_browser")
                
                # 设置服务选项以提高稳定性
                if service:
                    # 设置创建标志（Windows特定）
                    if platform.system().lower() == 'windows':
                        service.creation_flags = 0x08000000  # CREATE_NO_WINDOW标志
                        enhanced_logger.debug("设置Windows服务创建标志", "initialize_browser")
                    
                    # 设置服务参数
                    service.service_args = ['--verbose', '--log-path=nul']  # Windows下禁用日志输出
                    enhanced_logger.debug("Chrome服务参数配置完成", "initialize_browser")
                
                # 创建WebDriver实例
                self.driver = webdriver.Chrome(service=service, options=options)
                enhanced_logger.info(f"Chrome浏览器启动成功: {self.id}", "initialize_browser")
                
                # 将debug_port属性显式设置到WebDriver对象上，确保DevTools管理器能够访问
                setattr(self.driver, 'debug_port', self.debug_port)
                enhanced_logger.debug(f"将debug_port={self.debug_port}属性设置到WebDriver对象上", "initialize_browser")
                
                # 设置超时时间
                self.driver.set_script_timeout(30)
                self.driver.implicitly_wait(5)
                self.driver.set_page_load_timeout(60)
                
                # 执行反检测脚本和图片加载优化脚本
                enhanced_logger.debug("执行浏览器初始化脚本", "initialize_browser")
                
                # 分步执行JavaScript，增加错误处理和延迟
                try:
                    # 第一步：基础反检测脚本
                    enhanced_logger.debug("执行基础反检测脚本", "initialize_browser")
                    self.driver.execute_script("""
                        try {
                            // 反检测脚本 - 使用安全的方式
                            if (typeof navigator !== 'undefined' && navigator) {
                                Object.defineProperty(navigator, 'webdriver', {
                                    get: function() { return undefined; },
                                    configurable: true
                                });
                            }
                            
                            // 安全创建chrome对象
                            if (typeof window !== 'undefined' && window) {
                                window.chrome = window.chrome || {};
                                if (!window.chrome.runtime) {
                                    window.chrome.runtime = {};
                                }
                            }
                            
                            console.log('基础反检测脚本执行完成');
                        } catch (e) {
                            console.warn('基础反检测脚本执行失败:', e.message);
                        }
                    """)
                    enhanced_logger.debug("基础反检测脚本执行成功", "initialize_browser")
                    
                    # 第二步：图片加载优化脚本（延迟执行）
                    enhanced_logger.debug("准备执行图片加载优化脚本", "initialize_browser")
                    time.sleep(0.5)  # 短暂延迟确保页面环境稳定
                    
                    self.driver.execute_script("""
                        try {
                            // 图片加载优化脚本 - 使用更安全的方式
                            if (typeof window !== 'undefined' && window.Image && window.Image.prototype) {
                                // 安全地移除可能的图片拦截器
                                try {
                                    window.Image.prototype.onerror = null;
                                } catch (e) {
                                    console.warn('移除图片错误处理器失败:', e.message);
                                }
                            }
                            
                            // 安全的DOM操作包装函数
                            function safeDocumentOperation(operation) {
                                try {
                                    if (typeof document !== 'undefined' && document) {
                                        return operation();
                                    }
                                } catch (e) {
                                    console.warn('DOM操作失败:', e.message);
                                    return null;
                                }
                            }
                            
                            // 延迟执行DOM操作，确保文档加载完成
                            function setupImageOptimization() {
                                safeDocumentOperation(function() {
                                    // 移除可能的CSP限制
                                    try {
                                        if (document.head) {
                                            var existingCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
                                            if (existingCSP && existingCSP.remove) {
                                                existingCSP.remove();
                                            }
                                        }
                                    } catch (e) {
                                        console.warn('移除CSP失败:', e.message);
                                    }
                                    
                                    // 设置图片加载监听器
                                    try {
                                        var images = document.querySelectorAll('img');
                                        if (images && images.forEach) {
                                            images.forEach(function(img) {
                                                try {
                                                    if (img && img.src && !img.complete) {
                                                        if ('loading' in img) img.loading = 'eager';
                                                        if ('decoding' in img) img.decoding = 'sync';
                                                    }
                                                } catch (e) {
                                                    console.warn('图片属性设置失败:', e.message);
                                                }
                                            });
                                        }
                                    } catch (e) {
                                        console.warn('图片优化失败:', e.message);
                                    }
                                });
                            }
                            
                            // 根据文档状态选择执行时机
                            if (typeof document !== 'undefined' && document) {
                                if (document.readyState === 'loading') {
                                    // 文档还在加载，等待DOMContentLoaded
                                    document.addEventListener('DOMContentLoaded', setupImageOptimization);
                                } else {
                                    // 文档已加载，立即执行
                                    setupImageOptimization();
                                }
                            }
                            
                            console.log('图片加载优化脚本执行完成');
                        } catch (e) {
                            console.warn('图片加载优化脚本执行失败:', e.message);
                        }
                    """)
                    enhanced_logger.debug("图片加载优化脚本执行成功", "initialize_browser")
                    
                except Exception as js_error:
                    # JavaScript执行失败，记录警告但不阻止初始化过程
                    enhanced_logger.warning(f"JavaScript初始化脚本执行失败，但不影响正常使用: {js_error}", 
                                          "initialize_browser")
                    
                enhanced_logger.debug("浏览器初始化脚本执行完成", "initialize_browser")
                
                # 设置窗口大小并打开Telegram
                self.driver.set_window_size(1920, 1080)
                enhanced_logger.info(f"正在加载Telegram页面: {self.config.telegram_url}", 
                                   "initialize_browser")
                
                # 安全地加载页面，增加重试机制
                page_load_success = False
                max_load_attempts = 3
                
                # 记录页面加载开始
                self.network_manager.log_connection_attempt(self.instance_id, self.config.telegram_url, "GET")
                page_load_start_time = time.time()
                
                for attempt in range(max_load_attempts):
                    try:
                        enhanced_logger.debug(f"页面加载尝试 {attempt + 1}/{max_load_attempts}", "initialize_browser")
                        self.network_manager.log_network_event(
                            level='INFO',
                            category='PAGE_LOAD',
                            message=f"开始加载尝试 {attempt + 1}",
                            instance_id=self.instance_id,
                            attempt=attempt + 1
                        )
                        self.driver.get(self.config.telegram_url)
                        
                        # 等待页面基本加载完成
                        enhanced_logger.debug("等待页面基本加载完成", "initialize_browser")
                        time.sleep(2)  # 基础等待时间
                        
                        # 检查页面是否正常加载
                        page_state = self.driver.execute_script("return document.readyState;")
                        enhanced_logger.debug(f"页面状态检查: {page_state}", "initialize_browser")
                        
                        if page_state in ['interactive', 'complete']:
                            page_load_success = True
                            page_load_time = time.time() - page_load_start_time
                            enhanced_logger.info(f"页面加载成功 (状态: {page_state})", "initialize_browser")
                            
                            # 记录页面加载成功
                            self.network_manager.log_connection_success(
                                self.instance_id, 
                                self.config.telegram_url, 
                                page_load_time
                            )
                            self.network_manager.log_network_event(
                                level='INFO',
                                category='PAGE_LOAD',
                                message="页面加载成功",
                                instance_id=self.instance_id,
                                page_state=page_state,
                                load_time=page_load_time
                            )
                            break
                        else:
                            enhanced_logger.warning(f"页面状态异常: {page_state}, 重试加载", "initialize_browser")
                            self.network_manager.log_network_event(
                                level='WARNING',
                                category='PAGE_LOAD',
                                message="页面状态异常，准备重试",
                                instance_id=self.instance_id,
                                page_state=page_state
                            )
                            time.sleep(2)  # 等待后重试
                            
                    except Exception as load_error:
                        enhanced_logger.warning(f"页面加载尝试 {attempt + 1} 失败: {load_error}", "initialize_browser")
                        
                        # 记录页面加载失败
                        self.network_manager.log_network_event(
                            level='ERROR',
                            category='PAGE_LOAD',
                            message=f"页面加载失败 (尝试 {attempt + 1})",
                            instance_id=self.instance_id,
                            error=str(load_error)
                        )
                        
                        if attempt < max_load_attempts - 1:
                            time.sleep(3)  # 重试前等待更长时间
                        else:
                            enhanced_logger.error("页面加载最终失败", "initialize_browser")
                            
                            # 记录最终失败
                            self.network_manager.log_connection_failure(
                                self.instance_id, 
                                self.config.telegram_url, 
                                str(load_error)
                            )
                
                if not page_load_success:
                    enhanced_logger.warning("页面加载失败，尝试使用最小化启动选项重启浏览器", "initialize_browser")
                    # 记录失败并准备重启
                    self.network_manager.log_network_event(
                        level='WARNING',
                        category='PAGE_LOAD',
                        message='首次页面加载失败，准备使用最小化参数重启浏览器',
                        instance_id=self.instance_id
                    )

                    # 清理现有 driver
                    try:
                        self._cleanup_driver()
                    except Exception as cleanup_err:
                        enhanced_logger.warning(f"清理失败: {cleanup_err}", "initialize_browser")

                    # 构建最小化选项
                    minimal_options = Options()
                    minimal_options.add_argument('--no-sandbox')
                    minimal_options.add_argument('--disable-gpu')
                    # 最小化重启不启用 headless，以模拟手动 chrome --no-sandbox，可提升联网成功率
                    # if is_headless:
                    #     minimal_options.add_argument('--headless=new')

                    base_skip = [
                        '--no-sandbox',
                        '--disable-gpu',
                        '--disable-dev-shm-usage',
                        '--proxy-server="direct://"',
                        '--proxy-bypass-list=*'
                    ]
                    for opt in self.network_manager.get_minimal_chrome_options():
                        minimal_options.add_argument(opt)
                        # 记录
                        self.network_manager.log_chrome_option(self.instance_id, opt, "MINIMAL_STARTUP")

                    # 重启浏览器
                    enhanced_logger.info("使用最小化参数重启 Chrome", "initialize_browser")
                    self.driver = webdriver.Chrome(options=minimal_options)

                    # 再次尝试加载
                    try:
                        self.driver.get(self.config.telegram_url)
                        enhanced_logger.info("最小化参数加载页面成功", "initialize_browser")
                        self.network_manager.log_network_event(
                            level='INFO',
                            category='PAGE_LOAD',
                            message="最小化参数加载成功",
                            instance_id=self.instance_id
                        )
                    except Exception as min_err:
                        enhanced_logger.error(f"最小化参数加载仍然失败: {min_err}", "initialize_browser")
                        self.network_manager.log_connection_failure(
                            self.instance_id,
                            self.config.telegram_url,
                            str(min_err)
                        )
                        # 保持原有行为：继续后续流程但提示用户
                        enhanced_logger.warning("即使加载失败，仍继续后续初始化流程", "initialize_browser")
                
                # 额外等待确保页面稳定
                enhanced_logger.debug("等待页面完全稳定", "initialize_browser")
                time.sleep(3)  # 等待页面稳定
                
                # 验证图片加载设置（延迟执行，确保页面完全加载）
                try:
                    enhanced_logger.debug("开始验证图片加载设置", "initialize_browser")
                    self._verify_image_loading()
                except Exception as verify_error:
                    enhanced_logger.warning(f"图片加载验证失败，但不影响正常使用: {verify_error}", "initialize_browser")
                
                # 自动注入JavaScript模块（浏览器初始化完成后立即执行）
                enhanced_logger.info("开始自动注入js_modules中的JavaScript文件", "initialize_browser")
                try:
                    # 调用JavaScript注入方法，不传入file_path参数以触发批量注入
                    js_injection_success = self.inject_javascript()
                    
                    if js_injection_success:
                        enhanced_logger.info("自动JavaScript注入成功完成", "initialize_browser")
                    else:
                        enhanced_logger.warning("自动JavaScript注入失败，实例仍可正常使用", "initialize_browser")
                        
                except Exception as inject_error:
                    enhanced_logger.warning(f"自动JavaScript注入过程发生异常，实例仍可正常使用: {inject_error}", 
                                          "initialize_browser", inject_error)
                
                self.metadata.status = InstanceStatus.READY
                self.metadata.last_access = time.time()
                
                enhanced_logger.info(f"浏览器初始化完成，实例状态: {self.metadata.status}", "initialize_browser")
                return True
                
            except Exception as e:
                enhanced_logger.error(f"浏览器初始化失败: {e}", 
                                     "initialize_browser", e)
                
                # 更新实例状态为错误
                self.metadata.status = InstanceStatus.ERROR
                self.metadata.error_message = str(e)
                
                # 清理资源
                self._cleanup_driver()
                
                return False
    
    def inject_javascript(self, file_path: str = None) -> bool:
        """
        注入JavaScript代码
        
        Args:
            file_path: 可选的单个JavaScript文件路径，如果为None则注入所有js_modules中的文件
            
        Returns:
            是否注入成功
        """
        logger.info(f"开始注入JavaScript: {self.instance_id}, 文件: {file_path}", "TelegramInstance.inject_javascript")
        
        # 使用线程锁确保线程安全
        with self._lock:
            try:
                # 检查实例状态
                if self.metadata.status != InstanceStatus.READY:
                    logger.error(f"实例状态不正确，无法注入JavaScript: {self.instance_id}, 状态: {self.metadata.status}", 
                               "TelegramInstance.inject_javascript")
                    return False
                
                # 检查WebDriver是否可用
                if not self.driver:
                    logger.error(f"WebDriver不可用: {self.instance_id}", "TelegramInstance.inject_javascript")
                    return False
                
                # 获取JavaScript管理器
                logger.debug("获取JavaScript模块管理器", "TelegramInstance.inject_javascript")
                js_manager = get_js_manager()
                
                if file_path:
                    # 单文件注入模式
                    logger.info(f"单文件注入模式: {file_path}", "TelegramInstance.inject_javascript")
                    return self._inject_single_file(file_path)
                else:
                    # 模块批量注入模式
                    logger.info("模块批量注入模式: 注入js_modules中的所有文件", "TelegramInstance.inject_javascript")
                    return self._inject_all_modules(js_manager)
                
            except Exception as e:
                logger.error(f"JavaScript注入过程发生异常: {self.instance_id}", "TelegramInstance.inject_javascript", e)
                
                # 更新错误信息
                self.metadata.error_message = f"JavaScript注入失败: {str(e)}"
                
                return False
    
    def _inject_single_file(self, file_path: str) -> bool:
        """
        注入单个JavaScript文件
        
        Args:
            file_path: JavaScript文件路径
            
        Returns:
            是否注入成功
        """
        logger.info(f"开始单文件JavaScript注入: {file_path}", "TelegramInstance._inject_single_file")
        
        try:
            # 确定完整文件路径
            if not os.path.isabs(file_path):
                # 相对路径，使用配置中的默认路径或当前目录
                if file_path == self.config.js_file_path or not os.path.exists(file_path):
                    full_path = self.config.js_file_path
                else:
                    full_path = file_path
            else:
                full_path = file_path
            
            logger.debug(f"完整文件路径: {full_path}", "TelegramInstance._inject_single_file")
            
            # 检查文件是否存在
            if not os.path.exists(full_path):
                logger.error(f"JavaScript文件不存在: {full_path}", "TelegramInstance._inject_single_file")
                return False
            
            # 读取文件内容
            logger.debug(f"读取JavaScript文件内容: {full_path}", "TelegramInstance._inject_single_file")
            with open(full_path, 'r', encoding='utf-8') as f:
                js_content = f.read()
            
            logger.debug(f"JavaScript文件读取成功: 大小={len(js_content)} 字符", "TelegramInstance._inject_single_file")
            
            # 执行JavaScript代码
            logger.debug("执行JavaScript代码", "TelegramInstance._inject_single_file")
            result = self.driver.execute_script(js_content)
            
            # 更新注入状态
            self.metadata.js_injected = True
            self.metadata.last_access = time.time()
            
            logger.info(f"单文件JavaScript注入成功: {full_path}", "TelegramInstance._inject_single_file")
            return True
            
        except Exception as e:
            logger.error(f"单文件JavaScript注入失败: {file_path}", "TelegramInstance._inject_single_file", e)
            return False
    
    def _inject_all_modules(self, js_manager) -> bool:
        """
        注入所有JavaScript模块
        
        Args:
            js_manager: JavaScript模块管理器
            
        Returns:
            是否注入成功
        """
        logger.info("开始批量JavaScript模块注入", "TelegramInstance._inject_all_modules")
        
        try:
            # 获取合并的JavaScript内容
            logger.debug("获取合并的JavaScript内容", "TelegramInstance._inject_all_modules")
            combined_content = js_manager.get_combined_content(force_reload=False)
            
            # 检查内容是否为空
            if not combined_content or not combined_content.strip():
                logger.warning("JavaScript模块内容为空，可能没有找到有效的js文件", "TelegramInstance._inject_all_modules")
                
                # 尝试使用配置中的默认文件
                logger.info("尝试使用配置中的默认JavaScript文件", "TelegramInstance._inject_all_modules")
                return self._inject_single_file(self.config.js_file_path)
            
            logger.info(f"合并JavaScript内容获取成功: 总长度={len(combined_content)} 字符", 
                       "TelegramInstance._inject_all_modules")
            logger.debug(f"合并内容预览: {combined_content[:500]}{'...' if len(combined_content) > 500 else ''}", 
                        "TelegramInstance._inject_all_modules")
            
            # 分块执行JavaScript代码（避免单次执行过大的代码块）
            return self._execute_javascript_in_chunks(combined_content)
            
        except Exception as e:
            logger.error("批量JavaScript模块注入失败", "TelegramInstance._inject_all_modules", e)
            
            # 如果批量注入失败，尝试使用默认文件
            logger.warning("批量注入失败，尝试使用默认JavaScript文件", "TelegramInstance._inject_all_modules")
            try:
                return self._inject_single_file(self.config.js_file_path)
            except Exception as fallback_error:
                logger.error("默认文件注入也失败", "TelegramInstance._inject_all_modules", fallback_error)
                return False
    
    def _execute_javascript_in_chunks(self, js_content: str, chunk_size: int = 50000) -> bool:
        """
        分块执行JavaScript代码
        
        Args:
            js_content: JavaScript代码内容
            chunk_size: 每块的最大字符数
            
        Returns:
            是否执行成功
        """
        logger.info(f"开始分块执行JavaScript代码: 总长度={len(js_content)}, 块大小={chunk_size}", 
                   "TelegramInstance._execute_javascript_in_chunks")
        
        try:
            # 如果内容较小，直接执行
            if len(js_content) <= chunk_size:
                logger.debug("JavaScript代码较小，直接执行", "TelegramInstance._execute_javascript_in_chunks")
                
                result = self.driver.execute_script(js_content)
                
                # 更新注入状态
                self.metadata.js_injected = True
                self.metadata.last_access = time.time()
                
                logger.info("JavaScript代码执行成功", "TelegramInstance._execute_javascript_in_chunks")
                return True
            
            # 按模块分隔符拆分代码
            logger.debug("按模块分隔符拆分JavaScript代码", "TelegramInstance._execute_javascript_in_chunks")
            
            # 查找模块分隔符
            module_separator = "// ===== MODULE:"
            end_separator = "// ===== END OF MODULE:"
            
            # 如果包含模块分隔符，按模块执行
            if module_separator in js_content:
                return self._execute_modules_separately(js_content, module_separator, end_separator)
            
            # 否则按字符数分块
            return self._execute_by_character_chunks(js_content, chunk_size)
            
        except Exception as e:
            logger.error("分块执行JavaScript代码失败", "TelegramInstance._execute_javascript_in_chunks", e)
            return False
    
    def _execute_modules_separately(self, js_content: str, module_separator: str, end_separator: str) -> bool:
        """
        按模块分别执行JavaScript代码
        
        Args:
            js_content: JavaScript代码内容
            module_separator: 模块开始分隔符
            end_separator: 模块结束分隔符
            
        Returns:
            是否执行成功
        """
        logger.info("按模块分别执行JavaScript代码", "TelegramInstance._execute_modules_separately")
        
        try:
            # 分割模块
            parts = js_content.split(module_separator)
            executed_modules = 0
            
            for i, part in enumerate(parts):
                if not part.strip():
                    continue
                
                # 提取模块信息
                if i == 0:
                    # 第一部分可能是前置代码
                    if part.strip():
                        logger.debug(f"执行前置代码: 长度={len(part)}", "TelegramInstance._execute_modules_separately")
                        try:
                            self.driver.execute_script(part)
                            logger.debug("前置代码执行成功", "TelegramInstance._execute_modules_separately")
                        except Exception as e:
                            logger.warning(f"前置代码执行失败: {e}", "TelegramInstance._execute_modules_separately")
                    continue
                
                # 解析模块内容
                lines = part.split('\n')
                module_name = "未知模块"
                
                if lines and lines[0].strip():
                    # 提取模块名
                    header = lines[0].strip()
                    if '(' in header and ')' in header:
                        module_name = header.split('(')[0].strip()
                
                # 查找模块结束位置
                end_pos = part.find(end_separator)
                if end_pos != -1:
                    module_content = part[:end_pos]
                else:
                    module_content = part
                
                # 清理模块内容（移除头部注释行）
                module_lines = module_content.split('\n')[1:]  # 跳过第一行（模块标识）
                clean_content = '\n'.join(module_lines).strip()
                
                if clean_content:
                    logger.debug(f"执行模块: {module_name}, 内容长度: {len(clean_content)}", 
                               "TelegramInstance._execute_modules_separately")
                    
                    try:
                        # 添加错误处理包装
                        wrapped_content = f"""
                        try {{
                            {clean_content}
                            console.log('模块 {module_name} 执行成功');
                        }} catch (e) {{
                            console.warn('模块 {module_name} 执行失败:', e.message);
                        }}
                        """
                        
                        self.driver.execute_script(wrapped_content)
                        executed_modules += 1
                        logger.info(f"模块执行成功: {module_name}", "TelegramInstance._execute_modules_separately")
                        
                        # 短暂延迟，避免浏览器负载过高
                        time.sleep(0.1)
                        
                    except Exception as e:
                        logger.warning(f"模块执行失败: {module_name} - {e}", "TelegramInstance._execute_modules_separately")
                        # 继续执行其他模块
                        continue
            
            # 更新注入状态
            if executed_modules > 0:
                self.metadata.js_injected = True
                self.metadata.last_access = time.time()
                
                logger.info(f"模块化JavaScript代码执行完成: 成功={executed_modules}/{len(parts)-1}", 
                           "TelegramInstance._execute_modules_separately")
                return True
            else:
                logger.error("没有成功执行任何模块", "TelegramInstance._execute_modules_separately")
                return False
                
        except Exception as e:
            logger.error("模块化执行JavaScript代码失败", "TelegramInstance._execute_modules_separately", e)
            return False
    
    def _execute_by_character_chunks(self, js_content: str, chunk_size: int) -> bool:
        """
        按字符数分块执行JavaScript代码
        
        Args:
            js_content: JavaScript代码内容
            chunk_size: 每块的字符数
            
        Returns:
            是否执行成功
        """
        logger.info(f"按字符数分块执行JavaScript代码: 块大小={chunk_size}", 
                   "TelegramInstance._execute_by_character_chunks")
        
        try:
            total_chunks = (len(js_content) + chunk_size - 1) // chunk_size
            executed_chunks = 0
            
            for i in range(0, len(js_content), chunk_size):
                chunk = js_content[i:i + chunk_size]
                chunk_num = (i // chunk_size) + 1
                
                logger.debug(f"执行代码块 {chunk_num}/{total_chunks}: 长度={len(chunk)}", 
                           "TelegramInstance._execute_by_character_chunks")
                
                try:
                    # 添加错误处理包装
                    wrapped_chunk = f"""
                    try {{
                        {chunk}
                        console.log('代码块 {chunk_num} 执行成功');
                    }} catch (e) {{
                        console.warn('代码块 {chunk_num} 执行失败:', e.message);
                    }}
                    """
                    
                    self.driver.execute_script(wrapped_chunk)
                    executed_chunks += 1
                    
                    logger.debug(f"代码块执行成功: {chunk_num}", "TelegramInstance._execute_by_character_chunks")
                    
                    # 短暂延迟
                    time.sleep(0.1)
                    
                except Exception as e:
                    logger.warning(f"代码块执行失败: {chunk_num} - {e}", "TelegramInstance._execute_by_character_chunks")
                    # 继续执行其他块
                    continue
            
            # 更新注入状态
            if executed_chunks > 0:
                self.metadata.js_injected = True
                self.metadata.last_access = time.time()
                
                logger.info(f"分块JavaScript代码执行完成: 成功={executed_chunks}/{total_chunks}", 
                           "TelegramInstance._execute_by_character_chunks")
                return True
            else:
                logger.error("没有成功执行任何代码块", "TelegramInstance._execute_by_character_chunks")
                return False
                
        except Exception as e:
            logger.error("分块执行JavaScript代码失败", "TelegramInstance._execute_by_character_chunks", e)
            return False
    
    def execute_command(self, command: str, args: List[Any] = None) -> Dict[str, Any]:
        """执行JavaScript命令"""
        logger.info(f"执行JavaScript命令: {self.instance_id}, 命令: {command}", "TelegramInstance.execute_command")
        
        # 使用线程锁确保线程安全
        with self._lock:
            try:
                # 检查实例状态
                if self.metadata.status != InstanceStatus.READY:
                    logger.error(f"实例状态不正确，无法执行命令: {self.instance_id}, 状态: {self.metadata.status}", "TelegramInstance.execute_command")
                    return {
                        'success': False,
                        'message': f'实例状态不正确: {self.metadata.status}',
                        'error_code': 'INSTANCE_NOT_READY'
                    }
                
                # 检查WebDriver是否可用
                if not self.driver:
                    logger.error(f"WebDriver不可用: {self.instance_id}", "TelegramInstance.execute_command")
                    return {
                        'success': False,
                        'message': 'WebDriver不可用',
                        'error_code': 'WEBDRIVER_UNAVAILABLE'
                    }
                
                # 检查命令是否为空
                if not command or command.strip() == "":
                    logger.warning(f"尝试执行空命令: {self.instance_id}", "TelegramInstance.execute_command")
                    return {
                        'success': False,
                        'message': '命令不能为空',
                        'error_code': 'EMPTY_COMMAND'
                    }
                
                # 检查JavaScript是否已注入
                if not self.metadata.js_injected:
                    logger.warning(f"JavaScript未注入，尝试自动注入: {self.instance_id}", "TelegramInstance.execute_command")
                    
                    # 尝试自动注入JavaScript
                    if not self.inject_javascript():
                        logger.error(f"自动注入JavaScript失败: {self.instance_id}", "TelegramInstance.execute_command")
                        return {
                            'success': False,
                            'message': 'JavaScript未注入且自动注入失败',
                            'error_code': 'JS_NOT_INJECTED'
                        }
                
                # 构建JavaScript执行脚本（统一使用IIFE安全包装）
                try:
                    # 生成待执行的JavaScript片段
                    if args:
                        js_args = ', '.join([repr(arg) for arg in args])
                        original_expr = f"{command}({js_args})"
                    else:
                        original_expr = command  # 用户自行决定是否带 ()
                    
                    logger.debug(f"原始JavaScript表达式: {original_expr}", "TelegramInstance.execute_command")
                    
                    # IIFE 安全包装
                    safe_script = (
                        "return (function(){try{return (" + original_expr + ");}catch(e){return {_js_error:e.message||String(e)};}})();"
                    )
                    logger.debug(f"安全包装后脚本: {safe_script[:200]}...", "TelegramInstance.execute_command")
                    
                    start_time = time.time()
                    result = self.driver.execute_script(safe_script)
                    execution_time = time.time() - start_time
                    
                    # 处理错误结果
                    if isinstance(result, dict) and result.get('_js_error'):
                        error_msg = result['_js_error']
                        logger.warning(f"JavaScript执行错误: {error_msg}", "TelegramInstance.execute_command")
                        return {
                            'success': False,
                            'message': f'JavaScript错误: {error_msg}',
                            'error_code': 'JS_EXECUTION_ERROR',
                            'execution_time': execution_time,
                            'command': command,
                            'args': args
                        }
                    
                    # 更新最后访问时间
                    self.metadata.last_access = time.time()
                    
                    logger.info(f"JavaScript命令执行成功: {self.instance_id}, 命令: {command}, 耗时: {execution_time:.3f}秒", "TelegramInstance.execute_command")
                    
                    return {
                        'success': True,
                        'result': result,
                        'execution_time': execution_time,
                        'command': command,
                        'args': args
                    }
                    
                except Exception as js_error:
                    logger.error("内部JavaScript脚本执行异常", "TelegramInstance.execute_command", js_error)
                    self.metadata.error_message = f"命令执行失败: {str(js_error)}"
                    return {
                        'success': False,
                        'message': f'命令执行失败: {str(js_error)}',
                        'error_code': 'JS_EXECUTION_ERROR',
                        'command': command,
                        'args': args
                    }
            
            except Exception as js_error:
                logger.error("执行命令过程发生异常", "TelegramInstance.execute_command", js_error)
                self.metadata.error_message = f"命令执行失败: {str(js_error)}"
                return {
                    'success': False,
                    'message': f'命令执行失败: {str(js_error)}',
                    'error_code': 'EXECUTION_ERROR',
                    'command': command,
                    'args': args
                }
    
    def add_client(self, client_id: str) -> None:
        """添加连接的客户端"""
        logger.debug(f"添加连接客户端: {self.instance_id}, 客户端: {client_id}", "TelegramInstance.add_client")
        
        # 使用线程锁确保线程安全
        with self._lock:
            # 检查客户端是否已存在
            if client_id not in self.metadata.connected_clients:
                self.metadata.connected_clients.append(client_id)
                logger.info(f"客户端连接成功: {self.instance_id}, 客户端: {client_id}, 总连接数: {len(self.metadata.connected_clients)}", "TelegramInstance.add_client")
            else:
                logger.warning(f"客户端已存在: {self.instance_id}, 客户端: {client_id}", "TelegramInstance.add_client")
    
    def remove_client(self, client_id: str) -> None:
        """移除连接的客户端"""
        logger.debug(f"移除连接客户端: {self.instance_id}, 客户端: {client_id}", "TelegramInstance.remove_client")
        
        # 使用线程锁确保线程安全
        with self._lock:
            # 检查客户端是否存在
            if client_id in self.metadata.connected_clients:
                self.metadata.connected_clients.remove(client_id)
                logger.info(f"客户端断开连接: {self.instance_id}, 客户端: {client_id}, 剩余连接数: {len(self.metadata.connected_clients)}", "TelegramInstance.remove_client")
            else:
                logger.warning(f"客户端不存在: {self.instance_id}, 客户端: {client_id}", "TelegramInstance.remove_client")
    
    def _cleanup_driver(self) -> None:
        """清理WebDriver资源"""
        logger.debug(f"清理WebDriver资源: {self.instance_id}", "TelegramInstance._cleanup_driver")
        
        try:
            # 关闭WebDriver
            if hasattr(self, 'driver') and self.driver:
                self.driver.quit()
                self.driver = None
                logger.debug(f"WebDriver已关闭: {self.instance_id}", "TelegramInstance._cleanup_driver")
                
            # 停止Chrome服务
            if hasattr(self, 'service') and self.service:
                try:
                    self.service.stop()
                except Exception:
                    pass  # 忽略服务停止异常
                self.service = None
                logger.debug(f"Chrome服务已停止: {self.instance_id}", "TelegramInstance._cleanup_driver")
                
        except Exception as e:
            logger.error(f"清理WebDriver资源失败: {self.instance_id}", "TelegramInstance._cleanup_driver", e)
    
    def terminate(self) -> None:
        """终止实例"""
        logger.info(f"开始终止实例: {self.instance_id}", "TelegramInstance.terminate")
        
        with self._lock:
            try:
                # 禁用DevTools调试功能
                if self.metadata.devtools_enabled:
                    logger.debug(f"禁用DevTools调试功能: {self.instance_id}", "TelegramInstance.terminate")
                    try:
                        self.disable_devtools()
                    except Exception as e:
                        logger.warning(f"禁用DevTools调试功能失败: {e}", "TelegramInstance.terminate")
                
                # 更新实例状态
                logger.debug(f"更新实例状态为终止: {self.instance_id}", "TelegramInstance.terminate")
                self.metadata.status = InstanceStatus.TERMINATED
                
                # 清理WebDriver
                logger.debug(f"清理WebDriver: {self.instance_id}", "TelegramInstance.terminate")
                self._cleanup_driver()
                
                logger.info(f"实例终止完成: {self.instance_id}", "TelegramInstance.terminate")
                
            except Exception as e:
                logger.error(f"实例终止过程发生异常: {self.instance_id}", "TelegramInstance.terminate", e)
    
    def enable_devtools(self) -> Dict[str, Any]:
        """
        启用Chrome DevTools Protocol调试功能
        
        Returns:
            启用结果
        """
        logger.info(f"启用Chrome DevTools Protocol调试功能: {self.instance_id}", "enable_devtools")
        
        with self._lock:
            # 检查实例状态
            if self.metadata.status != InstanceStatus.READY:
                logger.error(f"实例状态不正确，无法启用DevTools: {self.instance_id}, 状态: {self.metadata.status}", "enable_devtools")
                return {
                    'success': False,
                    'message': f'实例状态不正确: {self.metadata.status}',
                    'error_code': 'INSTANCE_NOT_READY'
                }
            
            # 检查WebDriver是否可用
            if not self.driver:
                logger.error(f"WebDriver不可用: {self.instance_id}", "enable_devtools")
                return {
                    'success': False,
                    'message': 'WebDriver不可用',
                    'error_code': 'WEBDRIVER_UNAVAILABLE'
                }
            
            # 如果已启用，直接返回调试信息
            if self.metadata.devtools_enabled:
                logger.debug(f"DevTools已启用，获取调试信息: {self.instance_id}", "enable_devtools")
                return self.devtools_manager.get_debugging_info(self.instance_id)
            
            # 启用DevTools调试
            result = self.devtools_manager.enable_debugging_for_instance(self.instance_id, self.driver)
            
            if result.get('success'):
                # 更新元数据
                self.metadata.devtools_enabled = True
                self.metadata.last_access = time.time()
                logger.info(f"DevTools调试功能启用成功: {self.instance_id}", "enable_devtools")
            else:
                logger.error(f"DevTools调试功能启用失败: {self.instance_id}, {result.get('message')}", "enable_devtools")
            
            return result
    
    def get_devtools_info(self) -> Dict[str, Any]:
        """
        获取DevTools调试信息
        
        Returns:
            调试信息
        """
        logger.debug(f"获取DevTools调试信息: {self.instance_id}", "get_devtools_info")
        
        with self._lock:
            # 检查是否已启用DevTools
            if not self.metadata.devtools_enabled:
                logger.warning(f"DevTools未启用: {self.instance_id}", "get_devtools_info")
                return {
                    'success': False,
                    'message': 'DevTools未启用',
                    'error_code': 'DEVTOOLS_NOT_ENABLED'
                }
            
            # 获取调试信息
            result = self.devtools_manager.get_debugging_info(self.instance_id)
            
            if result.get('success'):
                # 更新最后访问时间
                self.metadata.last_access = time.time()
                logger.debug(f"获取DevTools调试信息成功: {self.instance_id}", "get_devtools_info")
            else:
                logger.warning(f"获取DevTools调试信息失败: {self.instance_id}, {result.get('message')}", "get_devtools_info")
            
            return result
    
    def create_devtools_connection(self) -> Dict[str, Any]:
        """
        创建DevTools WebSocket连接
        
        Returns:
            连接信息
        """
        logger.info(f"创建DevTools WebSocket连接: {self.instance_id}", "create_devtools_connection")
        
        with self._lock:
            # 检查是否已启用DevTools
            if not self.metadata.devtools_enabled:
                logger.warning(f"DevTools未启用，尝试自动启用: {self.instance_id}", "create_devtools_connection")
                
                # 尝试自动启用DevTools
                enable_result = self.enable_devtools()
                if not enable_result.get('success'):
                    logger.error(f"自动启用DevTools失败: {self.instance_id}", "create_devtools_connection")
                    return enable_result
            
            # 创建连接
            result = self.devtools_manager.create_connection(self.instance_id)
            
            if result.get('success'):
                # 更新最后访问时间
                self.metadata.last_access = time.time()
                logger.info(f"DevTools WebSocket连接创建成功: {self.instance_id}", "create_devtools_connection")
            else:
                logger.error(f"DevTools WebSocket连接创建失败: {self.instance_id}, {result.get('message')}", "create_devtools_connection")
            
            return result
    
    def disable_devtools(self) -> Dict[str, Any]:
        """
        禁用DevTools调试功能
        
        Returns:
            禁用结果
        """
        logger.info(f"禁用DevTools调试功能: {self.instance_id}", "disable_devtools")
        
        with self._lock:
            # 检查是否已启用DevTools
            if not self.metadata.devtools_enabled:
                logger.debug(f"DevTools未启用，无需禁用: {self.instance_id}", "disable_devtools")
                return {
                    'success': True,
                    'message': 'DevTools未启用，无需禁用'
                }
            
            # 禁用DevTools
            result = self.devtools_manager.disable_debugging_for_instance(self.instance_id)
            
            if result.get('success'):
                # 更新元数据
                self.metadata.devtools_enabled = False
                self.metadata.last_access = time.time()
                logger.info(f"DevTools调试功能禁用成功: {self.instance_id}", "disable_devtools")
            else:
                logger.error(f"DevTools调试功能禁用失败: {self.instance_id}, {result.get('message')}", "disable_devtools")
            
            return result

class InstancePool:
    """实例池管理器"""
    
    def __init__(self):
        """初始化实例池"""
        logger.info("初始化实例池管理器", "InstancePool.__init__")
        
        # 实例存储
        self.instances: Dict[str, TelegramInstance] = {}  # 实例ID -> 实例对象
        
        # 线程安全锁
        self._lock = threading.RLock()
        
        # 获取配置
        self.config = get_config()
        
        # 线程池（用于并发操作）
        self.executor = ThreadPoolExecutor(max_workers=self.config.thread_pool_size)
        
        # 启动清理守护线程
        self._start_cleanup_daemon()
        
        logger.info("实例池管理器初始化完成", "InstancePool.__init__")
    
    def _start_cleanup_daemon(self) -> None:
        """启动清理守护线程"""
        logger.info("启动实例清理守护线程", "InstancePool._start_cleanup_daemon")
        
        def cleanup_worker():
            """清理工作线程"""
            while True:
                try:
                    # 等待清理间隔
                    time.sleep(self.config.instance_cleanup_interval)
                    
                    # 执行清理操作
                    self._cleanup_expired_instances()
                    
                except Exception as e:
                    logger.error("实例清理守护线程异常", "InstancePool.cleanup_worker", e)
        
        # 创建守护线程
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        
        logger.info("实例清理守护线程启动成功", "InstancePool._start_cleanup_daemon")
    
    def _cleanup_expired_instances(self) -> None:
        """清理过期实例"""
        logger.debug("开始清理过期实例", "InstancePool._cleanup_expired_instances")
        
        # 使用线程锁确保线程安全
        with self._lock:
            try:
                current_time = time.time()
                expired_instances = []
                
                # 查找过期实例
                for instance_id, instance in self.instances.items():
                    # 检查实例是否过期（超过配置的超时时间且没有连接的客户端）
                    time_since_access = current_time - instance.metadata.last_access
                    has_clients = len(instance.metadata.connected_clients) > 0
                    
                    if time_since_access > self.config.instance_timeout and not has_clients:
                        expired_instances.append(instance_id)
                        logger.debug(f"发现过期实例: {instance_id}, 空闲时间: {time_since_access:.1f}秒", "InstancePool._cleanup_expired_instances")
                
                # 清理过期实例
                for instance_id in expired_instances:
                    logger.info(f"清理过期实例: {instance_id}", "InstancePool._cleanup_expired_instances")
                    self._destroy_instance_internal(instance_id)
                
                if expired_instances:
                    logger.info(f"清理完成，共清理 {len(expired_instances)} 个过期实例", "InstancePool._cleanup_expired_instances")
                else:
                    logger.debug("没有发现过期实例", "InstancePool._cleanup_expired_instances")
                    
            except Exception as e:
                logger.error("清理过期实例过程发生异常", "InstancePool._cleanup_expired_instances", e)
    
    def create_instance(self, name: str = None, group_id: str = None, profile_id: str = None) -> Dict[str, Any]:
        """创建新实例"""
        logger.info(f"创建新实例: 名称={name}, 分组={group_id}, 资料={profile_id}", "InstancePool.create_instance")
        
        # 使用线程锁确保线程安全
        with self._lock:
            try:
                # 验证必要参数
                if not group_id:
                    logger.error("创建实例失败: 缺少分组ID", "InstancePool.create_instance")
                    return {
                        'success': False,
                        'message': '分组ID是必需的',
                        'error_code': 'MISSING_GROUP_ID'
                    }
                
                if not profile_id:
                    logger.error("创建实例失败: 缺少用户资料ID", "InstancePool.create_instance")
                    return {
                        'success': False,
                        'message': '用户资料ID是必需的',
                        'error_code': 'MISSING_PROFILE_ID'
                    }
                
                # 检查实例数量限制
                if len(self.instances) >= self.config.max_instances:
                    logger.warning(f"实例数量已达上限: {len(self.instances)}/{self.config.max_instances}", "InstancePool.create_instance")
                    return {
                        'success': False,
                        'message': f'实例数量已达上限 ({self.config.max_instances})',
                        'error_code': 'MAX_INSTANCES_REACHED'
                    }
                
                # 生成实例ID
                instance_id = str(uuid.uuid4())
                
                # 创建实例对象
                instance = TelegramInstance(
                    instance_id=instance_id,
                    name=name,
                    group_id=group_id,
                    profile_id=profile_id
                )
                
                # 异步初始化浏览器（避免阻塞）
                def init_browser():
                    """异步初始化浏览器"""
                    try:
                        logger.debug(f"异步初始化浏览器开始: {instance_id}", "InstancePool.init_browser")
                        logger.debug(f"实例对象验证: instance={instance}, type={type(instance)}", "InstancePool.init_browser")
                        logger.debug(f"实例属性验证: instance.id={instance.id}, instance.metadata={instance.metadata}", "InstancePool.init_browser")
                        logger.debug(f"实例元数据验证: profile_id={instance.metadata.profile_id}, group_id={instance.metadata.group_id}", "InstancePool.init_browser")
                        
                        success = instance.initialize_browser()
                        
                        if not success:
                            logger.error(f"异步浏览器初始化失败: {instance_id}", "InstancePool.init_browser")
                            
                            # 从实例池中移除失败的实例
                            with self._lock:
                                if instance_id in self.instances:
                                    del self.instances[instance_id]
                        else:
                            logger.info(f"异步浏览器初始化成功: {instance_id}", "InstancePool.init_browser")
                            
                    except Exception as e:
                        logger.error(f"异步浏览器初始化异常: {instance_id}", "InstancePool.init_browser", e)
                        
                        # 从实例池中移除失败的实例
                        with self._lock:
                            if instance_id in self.instances:
                                del self.instances[instance_id]
                
                # 将实例添加到池中
                self.instances[instance_id] = instance
                
                # 提交异步初始化任务
                self.executor.submit(init_browser)
                
                logger.info(f"实例创建成功: {instance_id}, 当前实例数: {len(self.instances)}", "InstancePool.create_instance")
                
                return {
                    'success': True,
                    'instance_id': instance_id,
                    'instance': instance.metadata.to_dict(),
                    'message': '实例创建成功，正在初始化浏览器'
                }
                
            except Exception as e:
                logger.error("创建实例过程发生异常", "InstancePool.create_instance", e)
                return {
                    'success': False,
                    'message': f'创建实例失败: {str(e)}',
                    'error_code': 'INSTANCE_CREATION_FAILED'
                }
    
    def get_instance(self, instance_id: str) -> Optional[TelegramInstance]:
        """获取实例对象"""
        logger.debug(f"获取实例对象: {instance_id}", "InstancePool.get_instance")
        
        # 使用线程锁确保线程安全
        with self._lock:
            instance = self.instances.get(instance_id)
            
            if instance:
                logger.debug(f"实例对象获取成功: {instance_id}", "InstancePool.get_instance")
            else:
                logger.warning(f"实例不存在: {instance_id}", "InstancePool.get_instance")
            
            return instance
    
    def list_instances(self, group_id: str = None) -> List[Dict[str, Any]]:
        """列出实例"""
        logger.debug(f"列出实例，分组过滤: {group_id}", "InstancePool.list_instances")
        
        # 使用线程锁确保线程安全
        with self._lock:
            instances = []
            
            for instance in self.instances.values():
                # 应用分组过滤
                if group_id and instance.metadata.group_id != group_id:
                    continue
                
                instances.append(instance.metadata.to_dict())
            
            logger.debug(f"实例列表查询完成，总数: {len(instances)}", "InstancePool.list_instances")
            return instances
    
    def _destroy_instance_internal(self, instance_id: str) -> bool:
        """内部销毁实例方法（不加锁）"""
        try:
            # 获取实例
            instance = self.instances.get(instance_id)
            if not instance:
                logger.warning(f"要销毁的实例不存在: {instance_id}", "InstancePool._destroy_instance_internal")
                return False
            
            # 终止实例
            instance.terminate()
            
            # 从实例池中移除
            del self.instances[instance_id]
            
            logger.info(f"实例销毁成功: {instance_id}", "InstancePool._destroy_instance_internal")
            return True
            
        except Exception as e:
            logger.error(f"销毁实例失败: {instance_id}", "InstancePool._destroy_instance_internal", e)
            return False
    
    def destroy_instance(self, instance_id: str) -> Dict[str, Any]:
        """销毁实例"""
        logger.info(f"销毁实例: {instance_id}", "InstancePool.destroy_instance")
        
        # 使用线程锁确保线程安全
        with self._lock:
            try:
                # 调用内部销毁方法
                success = self._destroy_instance_internal(instance_id)
                
                if success:
                    return {
                        'success': True,
                        'message': '实例销毁成功',
                        'remaining_instances': len(self.instances)
                    }
                else:
                    return {
                        'success': False,
                        'message': '实例不存在或销毁失败',
                        'error_code': 'INSTANCE_DESTROY_FAILED'
                    }
                    
            except Exception as e:
                logger.error(f"销毁实例过程发生异常: {instance_id}", "InstancePool.destroy_instance", e)
                return {
                    'success': False,
                    'message': f'销毁实例失败: {str(e)}',
                    'error_code': 'INSTANCE_DESTROY_ERROR'
                }
    
    def shutdown(self) -> None:
        """关闭实例池"""
        logger.info("关闭实例池管理器", "InstancePool.shutdown")
        
        # 使用线程锁确保线程安全
        with self._lock:
            try:
                # 获取所有实例ID
                instance_ids = list(self.instances.keys())
                
                # 销毁所有实例
                for instance_id in instance_ids:
                    logger.debug(f"关闭实例: {instance_id}", "InstancePool.shutdown")
                    self._destroy_instance_internal(instance_id)
                
                # 关闭线程池
                self.executor.shutdown(wait=True)
                
                logger.info(f"实例池关闭完成，共销毁 {len(instance_ids)} 个实例", "InstancePool.shutdown")
                
            except Exception as e:
                logger.error("关闭实例池过程发生异常", "InstancePool.shutdown", e)

# 全局实例池管理器
instance_pool = InstancePool() 