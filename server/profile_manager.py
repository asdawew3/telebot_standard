#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
用户资料管理模块
管理浏览器用户资料（User Profile），每个资料包含独立的浏览器缓存、cookie、设置等
支持资料的创建、删除、备份、还原等操作
"""

import os
import json
import shutil
import time
import threading
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

from .logger import get_server_logger

# 获取服务端日志实例
logger = get_server_logger()

@dataclass
class ProfileInfo:
    """用户资料信息数据类"""
    id: str                        # 资料ID（唯一标识）
    name: str                      # 资料名称（显示名称）
    description: str               # 资料描述
    created_at: float             # 创建时间戳
    updated_at: float             # 更新时间戳
    last_used: float              # 最后使用时间
    is_active: bool               # 是否激活
    is_default: bool              # 是否为默认资料
    size_mb: float                # 资料大小（MB）
    path: str                     # 资料目录路径
    tags: List[str]               # 资料标签
    metadata: Dict[str, Any]      # 额外元数据
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        logger.debug(f"用户资料信息转换为字典: {self.id}", "ProfileInfo.to_dict")
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProfileInfo':
        """从字典创建用户资料信息对象"""
        logger.debug(f"从字典创建用户资料信息: {data.get('id', '未知')}", "ProfileInfo.from_dict")
        return cls(**data)

class ProfileManager:
    """用户资料管理器"""
    
    def __init__(self, profiles_dir: str = 'profiles', data_file: str = 'data/profiles.json'):
        """
        初始化用户资料管理器
        
        Args:
            profiles_dir: 用户资料存储目录
            data_file: 资料元数据存储文件
        """
        logger.info("初始化用户资料管理器", "ProfileManager.__init__")
        
        # 配置路径
        self.profiles_dir = profiles_dir
        self.data_file = data_file
        
        # 用户资料数据存储（资料ID -> 资料信息）
        self.profiles: Dict[str, ProfileInfo] = {}
        
        # 线程安全锁
        self._lock = threading.RLock()
        
        # 初始化目录结构
        self._ensure_directories()
        
        # 加载现有资料数据
        self._load_profiles()
        
        # 确保有默认资料
        self._ensure_default_profiles()
        
        # 清理无效资料
        self._cleanup_invalid_profiles()
        
        logger.info("用户资料管理器初始化完成", "ProfileManager.__init__")
    
    def _ensure_directories(self) -> None:
        """确保目录结构存在"""
        logger.debug("检查目录结构", "_ensure_directories")
        
        try:
            # 创建用户资料根目录
            if not os.path.exists(self.profiles_dir):
                logger.info(f"创建用户资料目录: {self.profiles_dir}", "_ensure_directories")
                os.makedirs(self.profiles_dir, exist_ok=True)
            
            # 创建数据目录
            data_dir = os.path.dirname(self.data_file)
            if data_dir and not os.path.exists(data_dir):
                logger.info(f"创建数据目录: {data_dir}", "_ensure_directories")
                os.makedirs(data_dir, exist_ok=True)
            
            logger.debug("目录结构检查完成", "_ensure_directories")
            
        except Exception as e:
            logger.error("创建目录结构失败", "_ensure_directories", e)
            raise
    
    def _load_profiles(self) -> None:
        """从文件加载用户资料数据"""
        logger.info("开始加载用户资料数据", "_load_profiles")
        
        with self._lock:
            try:
                # 检查数据文件是否存在
                if not os.path.exists(self.data_file):
                    logger.info("用户资料数据文件不存在，创建空数据", "_load_profiles")
                    self.profiles = {}
                    return
                
                # 读取数据文件
                logger.debug(f"读取用户资料数据文件: {self.data_file}", "_load_profiles")
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # 解析资料数据
                logger.debug(f"解析用户资料数据，数量: {len(data)}", "_load_profiles")
                self.profiles = {}
                
                for profile_id, profile_data in data.items():
                    try:
                        # 创建资料信息对象
                        profile_info = ProfileInfo.from_dict(profile_data)
                        
                        # 验证资料目录是否存在
                        if os.path.exists(profile_info.path):
                            self.profiles[profile_id] = profile_info
                            logger.debug(f"加载用户资料: {profile_id} - {profile_info.name}", "_load_profiles")
                        else:
                            logger.warning(f"用户资料目录不存在，跳过: {profile_id} - {profile_info.path}", "_load_profiles")
                        
                    except Exception as e:
                        logger.warning(f"加载用户资料失败: {profile_id}", "_load_profiles", e)
                        continue
                
                logger.info(f"用户资料数据加载完成，总数: {len(self.profiles)}", "_load_profiles")
                
            except json.JSONDecodeError as e:
                logger.error("用户资料数据文件格式错误", "_load_profiles", e)
                logger.warning("使用空资料数据", "_load_profiles")
                self.profiles = {}
                
            except Exception as e:
                logger.error("加载用户资料数据失败", "_load_profiles", e)
                self.profiles = {}
    
    def _save_profiles(self) -> None:
        """保存用户资料数据到文件"""
        logger.debug("开始保存用户资料数据", "_save_profiles")
        
        with self._lock:
            try:
                # 转换为字典格式
                data = {}
                for profile_id, profile_info in self.profiles.items():
                    data[profile_id] = profile_info.to_dict()
                
                logger.debug(f"准备保存用户资料数据，数量: {len(data)}", "_save_profiles")
                
                # 写入文件
                with open(self.data_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                
                logger.debug("用户资料数据保存完成", "_save_profiles")
                
            except Exception as e:
                logger.error("保存用户资料数据失败", "_save_profiles", e)
                raise
    
    def _ensure_default_profiles(self) -> None:
        """确保有默认用户资料"""
        logger.debug("检查默认用户资料", "_ensure_default_profiles")
        
        # 默认资料配置
        default_profiles = [
            {
                'id': 'default',
                'name': '默认资料',
                'description': '系统默认用户资料，包含基础浏览器设置',
                'is_default': True,
                'tags': ['default', 'system']
            },
            {
                'id': 'clean',
                'name': '干净资料',
                'description': '不包含任何缓存和cookie的干净资料',
                'is_default': False,
                'tags': ['clean', 'fresh']
            },
            {
                'id': 'test',
                'name': '测试资料',
                'description': '用于测试的用户资料',
                'is_default': False,
                'tags': ['test', 'development']
            }
        ]
        
        # 检查并创建默认资料
        created_count = 0
        for profile_config in default_profiles:
            if profile_config['id'] not in self.profiles:
                logger.info(f"创建默认用户资料: {profile_config['id']}", "_ensure_default_profiles")
                
                # 创建资料目录
                profile_path = os.path.join(self.profiles_dir, profile_config['id'])
                os.makedirs(profile_path, exist_ok=True)
                
                # 创建资料信息
                current_time = time.time()
                profile_info = ProfileInfo(
                    id=profile_config['id'],
                    name=profile_config['name'],
                    description=profile_config['description'],
                    created_at=current_time,
                    updated_at=current_time,
                    last_used=current_time,
                    is_active=True,
                    is_default=profile_config['is_default'],
                    size_mb=0.0,
                    path=profile_path,
                    tags=profile_config['tags'],
                    metadata={}
                )
                
                # 添加到资料列表
                self.profiles[profile_config['id']] = profile_info
                created_count += 1
        
        # 保存更新
        if created_count > 0:
            logger.info(f"创建了 {created_count} 个默认用户资料", "_ensure_default_profiles")
            self._save_profiles()
    
    def _cleanup_invalid_profiles(self) -> None:
        """清理无效的用户资料"""
        logger.debug("开始清理无效用户资料", "_cleanup_invalid_profiles")
        
        with self._lock:
            invalid_profiles = []
            
            # 检查每个资料
            for profile_id, profile_info in self.profiles.items():
                # 检查资料目录是否存在
                if not os.path.exists(profile_info.path):
                    logger.warning(f"用户资料目录不存在: {profile_id} - {profile_info.path}", "_cleanup_invalid_profiles")
                    invalid_profiles.append(profile_id)
            
            # 移除无效资料
            for profile_id in invalid_profiles:
                logger.info(f"移除无效用户资料: {profile_id}", "_cleanup_invalid_profiles")
                del self.profiles[profile_id]
            
            # 保存更新
            if invalid_profiles:
                logger.info(f"清理了 {len(invalid_profiles)} 个无效用户资料", "_cleanup_invalid_profiles")
                self._save_profiles()
    
    def _calculate_profile_size(self, profile_path: str) -> float:
        """
        计算用户资料目录大小
        
        Args:
            profile_path: 资料目录路径
            
        Returns:
            大小（MB）
        """
        logger.debug(f"计算用户资料大小: {profile_path}", "_calculate_profile_size")
        
        try:
            total_size = 0
            
            # 检查路径是否存在
            if not os.path.exists(profile_path):
                logger.debug(f"资料路径不存在: {profile_path}", "_calculate_profile_size")
                return 0.0
            
            # 遍历目录计算总大小
            for dirpath, dirnames, filenames in os.walk(profile_path):
                for filename in filenames:
                    try:
                        file_path = os.path.join(dirpath, filename)
                        if os.path.exists(file_path):
                            total_size += os.path.getsize(file_path)
                    except (OSError, IOError) as e:
                        # 忽略无法访问的文件
                        logger.debug(f"无法计算文件大小: {file_path}", "_calculate_profile_size", e)
                        continue
            
            # 转换为MB
            size_mb = total_size / (1024 * 1024)
            
            logger.debug(f"用户资料大小计算完成: {profile_path}, 大小: {size_mb:.2f} MB", "_calculate_profile_size")
            return round(size_mb, 2)
            
        except Exception as e:
            logger.error(f"计算用户资料大小失败: {profile_path}", "_calculate_profile_size", e)
            return 0.0
    
    def create_profile(self, profile_id: str = None, name: str = None, 
                      description: str = '', tags: Optional[List[str]] = None,
                      clone_from: Optional[str] = None) -> Dict[str, Any]:
        """
        创建新用户资料
        
        Args:
            profile_id: 资料ID（可选，自动生成）
            name: 资料名称
            description: 资料描述
            tags: 资料标签
            clone_from: 从指定资料克隆
            
        Returns:
            创建结果
        """
        logger.info(f"创建用户资料: {profile_id or '自动生成'} - {name or '自动命名'}", "create_profile")
        
        with self._lock:
            try:
                # 生成资料ID
                if not profile_id:
                    profile_id = str(uuid.uuid4())
                    logger.debug(f"自动生成资料ID: {profile_id}", "create_profile")
                
                # 验证资料ID
                if profile_id in self.profiles:
                    logger.warning(f"用户资料已存在: {profile_id}", "create_profile")
                    return {
                        'success': False,
                        'message': f'用户资料已存在: {profile_id}',
                        'error_code': 'PROFILE_EXISTS'
                    }
                
                # 生成资料名称
                if not name:
                    name = f"资料_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    logger.debug(f"自动生成资料名称: {name}", "create_profile")
                
                # 创建资料目录
                profile_path = os.path.join(self.profiles_dir, profile_id)
                logger.debug(f"创建用户资料目录: {profile_path}", "create_profile")
                os.makedirs(profile_path, exist_ok=True)
                
                # 处理克隆
                if clone_from:
                    logger.info(f"从资料克隆: {clone_from} -> {profile_id}", "create_profile")
                    
                    # 检查源资料是否存在
                    if clone_from not in self.profiles:
                        logger.warning(f"源用户资料不存在: {clone_from}", "create_profile")
                        return {
                            'success': False,
                            'message': f'源用户资料不存在: {clone_from}',
                            'error_code': 'SOURCE_PROFILE_NOT_FOUND'
                        }
                    
                    # 执行克隆
                    source_path = self.profiles[clone_from].path
                    try:
                        logger.debug(f"复制资料数据: {source_path} -> {profile_path}", "create_profile")
                        shutil.copytree(source_path, profile_path, dirs_exist_ok=True)
                        logger.debug(f"资料数据复制完成", "create_profile")
                    except Exception as e:
                        logger.error(f"克隆用户资料失败: {clone_from} -> {profile_id}", "create_profile", e)
                        # 清理已创建的目录
                        shutil.rmtree(profile_path, ignore_errors=True)
                        return {
                            'success': False,
                            'message': f'克隆用户资料失败: {str(e)}',
                            'error_code': 'CLONE_ERROR'
                        }
                
                # 计算资料大小
                logger.debug(f"计算用户资料大小: {profile_id}", "create_profile")
                profile_size = self._calculate_profile_size(profile_path)
                
                # 创建资料信息
                current_time = time.time()
                profile_info = ProfileInfo(
                    id=profile_id,
                    name=name.strip(),
                    description=description.strip(),
                    created_at=current_time,
                    updated_at=current_time,
                    last_used=current_time,
                    is_active=True,
                    is_default=False,
                    size_mb=profile_size,
                    path=profile_path,
                    tags=tags or [],
                    metadata={}
                )
                
                # 添加到资料列表
                self.profiles[profile_id] = profile_info
                logger.debug(f"用户资料添加到内存: {profile_id}", "create_profile")
                
                # 保存到文件
                self._save_profiles()
                
                logger.info(f"用户资料创建成功: {profile_id}", "create_profile")
                return {
                    'success': True,
                    'message': '用户资料创建成功',
                    'profile': profile_info.to_dict()
                }
                
            except Exception as e:
                logger.error(f"创建用户资料失败: {profile_id}", "create_profile", e)
                return {
                    'success': False,
                    'message': f'创建用户资料失败: {str(e)}',
                    'error_code': 'CREATE_ERROR'
                }
    
    def get_profile(self, profile_id: str) -> Optional[ProfileInfo]:
        """
        获取用户资料信息
        
        Args:
            profile_id: 资料ID
            
        Returns:
            资料信息或None
        """
        logger.debug(f"获取用户资料信息: {profile_id}", "get_profile")
        
        with self._lock:
            profile_info = self.profiles.get(profile_id)
            if profile_info:
                logger.debug(f"找到用户资料: {profile_id} - {profile_info.name}", "get_profile")
                
                # 更新最后使用时间
                profile_info.last_used = time.time()
                
                # 更新资料大小
                profile_info.size_mb = self._calculate_profile_size(profile_info.path)
                
            else:
                logger.debug(f"用户资料不存在: {profile_id}", "get_profile")
            
            return profile_info
    
    def list_profiles(self, include_inactive: bool = False) -> List[Dict[str, Any]]:
        """
        获取用户资料列表
        
        Args:
            include_inactive: 是否包含非激活资料
            
        Returns:
            资料列表
        """
        logger.debug(f"获取用户资料列表，包含非激活: {include_inactive}", "list_profiles")
        
        with self._lock:
            profiles = []
            
            for profile_info in self.profiles.values():
                # 检查激活状态
                if not include_inactive and not profile_info.is_active:
                    logger.debug(f"跳过非激活用户资料: {profile_info.id}", "list_profiles")
                    continue
                
                # 更新资料大小
                profile_info.size_mb = self._calculate_profile_size(profile_info.path)
                
                profiles.append(profile_info.to_dict())
            
            logger.debug(f"返回用户资料列表，数量: {len(profiles)}", "list_profiles")
            return profiles
    
    def delete_profile(self, profile_id: str, remove_files: bool = True) -> Dict[str, Any]:
        """
        删除用户资料
        
        Args:
            profile_id: 资料ID
            remove_files: 是否删除资料文件
            
        Returns:
            删除结果
        """
        logger.info(f"删除用户资料: {profile_id}, 删除文件: {remove_files}", "delete_profile")
        
        with self._lock:
            try:
                # 检查资料是否存在
                if profile_id not in self.profiles:
                    logger.warning(f"用户资料不存在: {profile_id}", "delete_profile")
                    return {
                        'success': False,
                        'message': f'用户资料不存在: {profile_id}',
                        'error_code': 'PROFILE_NOT_FOUND'
                    }
                
                # 检查是否为默认资料
                profile_info = self.profiles[profile_id]
                if profile_info.is_default:
                    logger.warning(f"不能删除默认用户资料: {profile_id}", "delete_profile")
                    return {
                        'success': False,
                        'message': f'不能删除默认用户资料: {profile_id}',
                        'error_code': 'CANNOT_DELETE_DEFAULT_PROFILE'
                    }
                
                # 删除资料文件
                if remove_files and os.path.exists(profile_info.path):
                    logger.debug(f"删除用户资料文件: {profile_info.path}", "delete_profile")
                    try:
                        shutil.rmtree(profile_info.path)
                        logger.debug(f"用户资料文件删除成功: {profile_info.path}", "delete_profile")
                    except Exception as e:
                        logger.error(f"删除用户资料文件失败: {profile_info.path}", "delete_profile", e)
                        return {
                            'success': False,
                            'message': f'删除用户资料文件失败: {str(e)}',
                            'error_code': 'DELETE_FILES_ERROR'
                        }
                
                # 从内存中删除
                del self.profiles[profile_id]
                logger.debug(f"用户资料从内存中删除: {profile_id}", "delete_profile")
                
                # 保存到文件
                self._save_profiles()
                
                logger.info(f"用户资料删除成功: {profile_id}", "delete_profile")
                return {
                    'success': True,
                    'message': '用户资料删除成功'
                }
                
            except Exception as e:
                logger.error(f"删除用户资料失败: {profile_id}", "delete_profile", e)
                return {
                    'success': False,
                    'message': f'删除用户资料失败: {str(e)}',
                    'error_code': 'DELETE_ERROR'
                }
    
    def validate_profile(self, profile_id: str) -> bool:
        """
        验证用户资料是否有效且可用
        
        Args:
            profile_id: 资料ID
            
        Returns:
            是否有效
        """
        logger.debug(f"验证用户资料: {profile_id}", "validate_profile")
        
        with self._lock:
            profile_info = self.profiles.get(profile_id)
            if not profile_info:
                logger.debug(f"用户资料不存在: {profile_id}", "validate_profile")
                return False
            
            if not profile_info.is_active:
                logger.debug(f"用户资料未激活: {profile_id}", "validate_profile")
                return False
            
            if not os.path.exists(profile_info.path):
                logger.debug(f"用户资料目录不存在: {profile_id} - {profile_info.path}", "validate_profile")
                return False
            
            logger.debug(f"用户资料验证通过: {profile_id}", "validate_profile")
            return True

# 全局用户资料管理器实例
profile_manager = ProfileManager() 

def get_profile_manager() -> ProfileManager:
    """
    获取全局用户资料管理器实例
    
    Returns:
        用户资料管理器实例
    """
    global profile_manager
    
    if profile_manager is None:
        logger.info("创建全局用户资料管理器实例", "get_profile_manager")
        profile_manager = ProfileManager()
    else:
        logger.debug("返回现有用户资料管理器实例", "get_profile_manager")
    
    return profile_manager 