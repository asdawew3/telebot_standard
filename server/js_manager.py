#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JavaScript模块管理器
负责管理和注入js_modules文件夹中的JavaScript文件
提供模块化的JavaScript代码管理功能
"""

import os
import sys
import time
import glob
from typing import List, Dict, Any, Optional
from pathlib import Path

from .logger import get_server_logger

# 获取服务端日志实例
logger = get_server_logger()

class JavaScriptModule:
    """JavaScript模块封装类"""
    
    def __init__(self, file_path: str):
        """
        初始化JavaScript模块
        
        Args:
            file_path: JavaScript文件路径
        """
        logger.debug(f"初始化JavaScript模块: {file_path}", "JavaScriptModule.__init__")
        
        # 基本属性设置
        self.file_path = os.path.abspath(file_path)  # 绝对路径
        self.file_name = os.path.basename(file_path)  # 文件名
        self.module_name = os.path.splitext(self.file_name)[0]  # 模块名（不含扩展名）
        
        # 模块状态
        self.content = None          # 文件内容
        self.size = 0               # 文件大小
        self.last_modified = 0      # 最后修改时间
        self.load_time = 0          # 加载时间
        self.is_loaded = False      # 是否已加载
        self.load_error = None      # 加载错误信息
        
        logger.debug(f"JavaScript模块基本信息: name={self.module_name}, path={self.file_path}", 
                    "JavaScriptModule.__init__")
        
        # 验证文件存在性
        if not os.path.exists(self.file_path):
            error_msg = f"JavaScript文件不存在: {self.file_path}"
            logger.error(error_msg, "JavaScriptModule.__init__")
            self.load_error = error_msg
        else:
            logger.debug(f"JavaScript文件存在性验证通过: {self.file_path}", "JavaScriptModule.__init__")
        
        logger.info(f"JavaScript模块初始化完成: {self.module_name}", "JavaScriptModule.__init__")
    
    def load_content(self) -> bool:
        """
        加载JavaScript文件内容
        
        Returns:
            是否加载成功
        """
        logger.info(f"开始加载JavaScript模块内容: {self.module_name}", "JavaScriptModule.load_content")
        
        try:
            # 检查文件是否存在
            if not os.path.exists(self.file_path):
                error_msg = f"JavaScript文件不存在: {self.file_path}"
                logger.error(error_msg, "JavaScriptModule.load_content")
                self.load_error = error_msg
                return False
            
            # 获取文件统计信息
            file_stat = os.stat(self.file_path)
            self.size = file_stat.st_size
            self.last_modified = file_stat.st_mtime
            
            logger.debug(f"文件统计信息: size={self.size} bytes, modified={self.last_modified}", 
                        "JavaScriptModule.load_content")
            
            # 读取文件内容
            logger.debug(f"开始读取文件内容: {self.file_path}", "JavaScriptModule.load_content")
            with open(self.file_path, 'r', encoding='utf-8') as f:
                self.content = f.read()
            
            # 更新加载状态
            self.load_time = time.time()
            self.is_loaded = True
            self.load_error = None
            
            logger.info(f"JavaScript模块内容加载成功: {self.module_name}, 大小: {self.size} bytes, 内容长度: {len(self.content)} 字符", 
                       "JavaScriptModule.load_content")
            logger.debug(f"模块内容预览: {self.content[:200]}{'...' if len(self.content) > 200 else ''}", 
                        "JavaScriptModule.load_content")
            
            return True
            
        except UnicodeDecodeError as e:
            error_msg = f"文件编码错误: {self.file_path} - {str(e)}"
            logger.error(error_msg, "JavaScriptModule.load_content")
            self.load_error = error_msg
            return False
            
        except PermissionError as e:
            error_msg = f"文件权限错误: {self.file_path} - {str(e)}"
            logger.error(error_msg, "JavaScriptModule.load_content")
            self.load_error = error_msg
            return False
            
        except Exception as e:
            error_msg = f"加载JavaScript文件失败: {self.file_path} - {str(e)}"
            logger.error(error_msg, "JavaScriptModule.load_content", e)
            self.load_error = error_msg
            return False
    
    def get_content(self, force_reload: bool = False) -> Optional[str]:
        """
        获取JavaScript内容
        
        Args:
            force_reload: 是否强制重新加载
            
        Returns:
            JavaScript内容，如果加载失败返回None
        """
        logger.debug(f"获取JavaScript模块内容: {self.module_name}, 强制重载: {force_reload}", 
                    "JavaScriptModule.get_content")
        
        # 检查是否需要加载或重新加载
        need_load = force_reload or not self.is_loaded
        
        if need_load:
            logger.debug(f"需要重新加载模块内容: {self.module_name}", "JavaScriptModule.get_content")
            
            # 重新加载内容
            if not self.load_content():
                logger.error(f"模块内容加载失败: {self.module_name} - {self.load_error}", 
                           "JavaScriptModule.get_content")
                return None
        else:
            logger.debug(f"使用缓存的模块内容: {self.module_name}", "JavaScriptModule.get_content")
        
        return self.content


class JavaScriptModuleManager:
    """JavaScript模块管理器"""
    
    def __init__(self, modules_dir: str = 'js_modules'):
        """
        初始化JavaScript模块管理器
        
        Args:
            modules_dir: JavaScript模块目录
        """
        logger.info(f"初始化JavaScript模块管理器: {modules_dir}", "JavaScriptModuleManager.__init__")
        
        # 基本设置
        self.modules_dir = os.path.abspath(modules_dir)  # 模块目录绝对路径
        self.modules = {}  # 模块字典 {module_name: JavaScriptModule}
        self.load_order = []  # 加载顺序
        self.last_scan_time = 0  # 最后扫描时间
        
        logger.debug(f"模块目录路径: {self.modules_dir}", "JavaScriptModuleManager.__init__")
        
        # 验证模块目录
        if not os.path.exists(self.modules_dir):
            logger.warning(f"JavaScript模块目录不存在: {self.modules_dir}，将尝试创建", "JavaScriptModuleManager.__init__")
            try:
                # 尝试创建模块目录
                os.makedirs(self.modules_dir, exist_ok=True)
                logger.info(f"JavaScript模块目录创建成功: {self.modules_dir}", "JavaScriptModuleManager.__init__")
            except Exception as create_error:
                logger.error(f"创建JavaScript模块目录失败: {self.modules_dir}", "JavaScriptModuleManager.__init__", create_error)
        elif not os.path.isdir(self.modules_dir):
            logger.error(f"JavaScript模块路径不是目录: {self.modules_dir}", "JavaScriptModuleManager.__init__")
        else:
            logger.debug(f"JavaScript模块目录验证通过: {self.modules_dir}", "JavaScriptModuleManager.__init__")
        
        # 扫描并加载模块
        self.scan_modules()
        
        logger.info(f"JavaScript模块管理器初始化完成，共发现 {len(self.modules)} 个模块", 
                   "JavaScriptModuleManager.__init__")
    
    def scan_modules(self) -> int:
        """
        扫描JavaScript模块目录
        
        Returns:
            发现的模块数量
        """
        logger.info(f"开始扫描JavaScript模块目录: {self.modules_dir}", "JavaScriptModuleManager.scan_modules")
        
        try:
            # 检查目录是否存在
            if not os.path.exists(self.modules_dir):
                logger.warning(f"模块目录不存在，跳过扫描: {self.modules_dir}", "JavaScriptModuleManager.scan_modules")
                return 0
            
            # 查找所有JavaScript文件
            js_pattern = os.path.join(self.modules_dir, '*.js')
            js_files = glob.glob(js_pattern)
            
            logger.debug(f"找到JavaScript文件: {js_files}", "JavaScriptModuleManager.scan_modules")
            
            # 清空现有模块（重新扫描）
            old_module_count = len(self.modules)
            self.modules.clear()
            self.load_order.clear()
            
            logger.debug(f"清空现有模块，原有模块数: {old_module_count}", "JavaScriptModuleManager.scan_modules")
            
            # 处理每个JavaScript文件
            for js_file in sorted(js_files):  # 按文件名排序确保加载顺序一致
                try:
                    logger.debug(f"处理JavaScript文件: {js_file}", "JavaScriptModuleManager.scan_modules")
                    
                    # 创建模块对象
                    module = JavaScriptModule(js_file)
                    
                    # 避免模块名冲突
                    module_name = module.module_name
                    original_name = module_name
                    counter = 1
                    
                    while module_name in self.modules:
                        module_name = f"{original_name}_{counter}"
                        counter += 1
                        logger.debug(f"模块名冲突，使用新名称: {module_name}", "JavaScriptModuleManager.scan_modules")
                    
                    # 更新模块名
                    module.module_name = module_name
                    
                    # 添加到管理器
                    self.modules[module_name] = module
                    self.load_order.append(module_name)
                    
                    logger.info(f"JavaScript模块添加成功: {module_name} ({js_file})", 
                               "JavaScriptModuleManager.scan_modules")
                    
                except Exception as e:
                    logger.error(f"处理JavaScript文件失败: {js_file}", "JavaScriptModuleManager.scan_modules", e)
                    continue
            
            # 更新扫描时间
            self.last_scan_time = time.time()
            
            logger.info(f"JavaScript模块扫描完成，发现 {len(self.modules)} 个模块: {list(self.modules.keys())}", 
                       "JavaScriptModuleManager.scan_modules")
            
            return len(self.modules)
            
        except Exception as e:
            logger.error(f"扫描JavaScript模块目录失败: {self.modules_dir}", "JavaScriptModuleManager.scan_modules", e)
            return 0
    
    def get_combined_content(self, modules: Optional[List[str]] = None, force_reload: bool = False) -> str:
        """
        获取合并的JavaScript内容
        
        Args:
            modules: 要合并的模块列表，None表示所有模块
            force_reload: 是否强制重新加载
            
        Returns:
            合并的JavaScript代码
        """
        logger.info(f"获取合并的JavaScript内容，模块: {modules or '全部'}, 强制重载: {force_reload}", 
                   "JavaScriptModuleManager.get_combined_content")
        
        # 确定要处理的模块列表
        if modules is None:
            target_modules = self.load_order
        else:
            target_modules = [name for name in modules if name in self.modules]
            logger.debug(f"指定模块过滤后: {target_modules}", "JavaScriptModuleManager.get_combined_content")
        
        # 收集所有模块内容
        combined_parts = []
        success_count = 0
        
        for module_name in target_modules:
            logger.debug(f"处理模块: {module_name}", "JavaScriptModuleManager.get_combined_content")
            
            module = self.modules.get(module_name)
            if not module:
                logger.warning(f"模块不存在，跳过: {module_name}", "JavaScriptModuleManager.get_combined_content")
                continue
            
            # 获取模块内容
            content = module.get_content(force_reload)
            if content:
                # 添加模块分隔注释
                separator = f"\n\n// ===== MODULE: {module_name} ({module.file_name}) =====\n"
                combined_parts.append(separator)
                combined_parts.append(content)
                combined_parts.append(f"\n// ===== END OF MODULE: {module_name} =====\n\n")
                
                success_count += 1
                logger.debug(f"模块内容添加成功: {module_name}, 内容长度: {len(content)}", 
                           "JavaScriptModuleManager.get_combined_content")
            else:
                logger.error(f"模块内容获取失败: {module_name} - {module.load_error}", 
                           "JavaScriptModuleManager.get_combined_content")
        
        # 合并所有内容
        combined_content = ''.join(combined_parts)
        
        logger.info(f"JavaScript内容合并完成，成功模块: {success_count}/{len(target_modules)}, 总长度: {len(combined_content)}", 
                   "JavaScriptModuleManager.get_combined_content")
        logger.debug(f"合并内容预览: {combined_content[:300]}{'...' if len(combined_content) > 300 else ''}", 
                    "JavaScriptModuleManager.get_combined_content")
        
        return combined_content
    
    def list_modules(self) -> List[Dict[str, Any]]:
        """
        获取模块列表信息
        
        Returns:
            模块信息列表
        """
        logger.debug("获取JavaScript模块列表", "JavaScriptModuleManager.list_modules")
        
        module_list = []
        
        for module_name in self.load_order:
            module = self.modules.get(module_name)
            if module:
                module_info = {
                    'name': module.module_name,
                    'file_name': module.file_name,
                    'file_path': module.file_path,
                    'size': module.size,
                    'is_loaded': module.is_loaded,
                    'load_error': module.load_error,
                    'last_modified': module.last_modified,
                    'load_time': module.load_time
                }
                module_list.append(module_info)
        
        logger.debug(f"返回 {len(module_list)} 个模块信息", "JavaScriptModuleManager.list_modules")
        return module_list


# 全局模块管理器实例
_js_manager = None

def get_js_manager() -> JavaScriptModuleManager:
    """
    获取全局JavaScript模块管理器实例
    
    Returns:
        JavaScript模块管理器实例
    """
    global _js_manager
    
    if _js_manager is None:
        logger.info("创建全局JavaScript模块管理器实例", "get_js_manager")
        _js_manager = JavaScriptModuleManager()
    else:
        logger.debug("返回现有JavaScript模块管理器实例", "get_js_manager")
    
    return _js_manager 