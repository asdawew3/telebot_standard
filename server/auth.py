#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Flask-Login认证系统
提供用户登录、注销、权限验证等功能
使用Flask-Login库实现会话管理和用户认证
"""

import os
import time
import hashlib
import secrets
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass

from flask import request, jsonify, session, current_app
from flask_login import UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from .logger import get_server_logger

# 获取服务端日志实例
logger = get_server_logger()

@dataclass
class UserAccount:
    """用户账户数据类"""
    username: str           # 用户名
    password_hash: str      # 密码哈希值
    permissions: List[str]  # 用户权限列表
    created_at: float       # 创建时间
    last_login: float       # 最后登录时间
    is_active: bool         # 账户是否激活
    login_attempts: int     # 登录尝试次数
    locked_until: float     # 锁定到期时间

class User(UserMixin):
    """Flask-Login用户类"""
    
    def __init__(self, username: str, account: UserAccount):
        """
        初始化用户对象
        
        Args:
            username: 用户名
            account: 用户账户数据
        """
        logger.debug(f"初始化用户对象: {username}", "User.__init__")
        
        # 设置用户基本信息
        self.id = username           # Flask-Login要求的用户ID
        self.username = username     # 用户名
        self.account = account       # 用户账户数据
        
        logger.debug(f"用户对象初始化完成: {username}, 权限: {account.permissions}", "User.__init__")
    
    def get_id(self):
        """获取用户ID（Flask-Login要求）"""
        logger.debug(f"获取用户ID: {self.id}", "User.get_id")
        return self.id
    
    def is_authenticated(self):
        """检查用户是否已认证（Flask-Login要求）"""
        logger.debug(f"检查用户认证状态: {self.username}", "User.is_authenticated")
        return True
    
    def is_active(self):
        """检查用户是否激活（Flask-Login要求）"""
        is_active = self.account.is_active
        logger.debug(f"检查用户激活状态: {self.username}, 激活: {is_active}", "User.is_active")
        return is_active
    
    def is_anonymous(self):
        """检查用户是否匿名（Flask-Login要求）"""
        logger.debug(f"检查用户匿名状态: {self.username}", "User.is_anonymous")
        return False
    
    def has_permission(self, permission: str) -> bool:
        """检查用户是否有指定权限"""
        logger.debug(f"检查用户权限: {self.username}, 权限: {permission}", "User.has_permission")
        
        # 检查用户是否有'all'权限（超级管理员）
        if 'all' in self.account.permissions:
            logger.debug(f"用户有全部权限: {self.username}", "User.has_permission")
            return True
        
        # 检查用户是否有指定权限
        has_perm = permission in self.account.permissions
        logger.debug(f"用户权限检查结果: {self.username}, 权限: {permission}, 结果: {has_perm}", "User.has_permission")
        return has_perm

class AuthManager:
    """认证管理器"""
    
    def __init__(self):
        """初始化认证管理器"""
        logger.info("初始化认证管理器", "AuthManager.__init__")
        
        # 用户账户存储（实际应用中应该使用数据库）
        self.accounts: Dict[str, UserAccount] = {}
        
        # 认证配置
        self.config = {
            'session_timeout': 86400 * 7,     # 会话超时时间（7天）
            'max_login_attempts': 5,          # 最大登录尝试次数
            'lockout_duration': 1800,         # 锁定持续时间（30分钟）
            'password_min_length': 8,         # 密码最小长度
            'require_complex_password': True, # 是否要求复杂密码
            'token_refresh_window': 86400     # 令牌刷新窗口期（1天）
        }
        
        # 用户令牌存储（用户名 -> token_id -> 令牌信息）
        # 允许同一账户在多个客户端/浏览器同时登录，互不影响
        self.user_tokens: Dict[str, Dict[str, Dict]] = {}
        
        # 反向映射：token_id -> username，用于仅凭token快速定位用户
        self.token_to_user: Dict[str, str] = {}
        
        # 初始化默认管理员账户
        self._init_default_accounts()
        
        logger.info("认证管理器初始化完成", "AuthManager.__init__")
    
    def _init_default_accounts(self):
        """初始化默认管理员账户"""
        logger.info("初始化默认管理员账户", "AuthManager._init_default_accounts")
        
        # 默认管理员账户配置
        default_accounts = {
            '10086': {
                'password': 'Kx7#mP9$nL2@wZ8!qR4%fH6^dG1&yU3*',
                'permissions': ['all']  # 超级管理员权限
            },
            '10087': {
                'password': 'Kx7#mP9$nL2@wZ8!qR4%fH6^dG1&yU3*',
                'permissions': ['all']  # 普通管理员权限
            }
        }
        
        # 创建默认账户
        current_time = time.time()
        for username, info in default_accounts.items():
            logger.debug(f"创建默认账户: {username}", "AuthManager._init_default_accounts")
            
            # 生成密码哈希
            password_hash = generate_password_hash(info['password'])
            
            # 创建用户账户
            account = UserAccount(
                username=username,
                password_hash=password_hash,
                permissions=info['permissions'],
                created_at=current_time,
                last_login=0,
                is_active=True,
                login_attempts=0,
                locked_until=0
            )
            
            # 存储账户
            self.accounts[username] = account
            
            logger.info(f"默认账户创建完成: {username}, 权限: {info['permissions']}", "AuthManager._init_default_accounts")
    
    def get_user(self, username: str) -> Optional[User]:
        """获取用户对象"""
        logger.debug(f"获取用户对象: {username}", "AuthManager.get_user")
        
        # 检查用户是否存在
        if username not in self.accounts:
            logger.warning(f"用户不存在: {username}", "AuthManager.get_user")
            return None
        
        # 获取用户账户
        account = self.accounts[username]
        
        # 创建用户对象
        user = User(username, account)
        
        logger.debug(f"用户对象获取成功: {username}", "AuthManager.get_user")
        return user
    
    def authenticate_user(self, username: str, password: str) -> Dict[str, any]:
        """用户认证"""
        logger.info(f"开始用户认证: {username}", "AuthManager.authenticate_user")
        
        try:
            # 检查用户是否存在
            if username not in self.accounts:
                logger.warning(f"认证失败: 用户不存在 - {username}", "AuthManager.authenticate_user")
                return {
                    'success': False,
                    'message': '用户名或密码错误',
                    'error_code': 'USER_NOT_FOUND'
                }
            
            # 获取用户账户
            account = self.accounts[username]
            
            # 检查账户是否被锁定
            current_time = time.time()
            if account.locked_until > current_time:
                remaining_time = int(account.locked_until - current_time)
                logger.warning(f"认证失败: 账户被锁定 - {username}, 剩余时间: {remaining_time}秒", "AuthManager.authenticate_user")
                return {
                    'success': False,
                    'message': f'账户已被锁定，请{remaining_time}秒后重试',
                    'error_code': 'ACCOUNT_LOCKED'
                }
            
            # 验证密码
            if not check_password_hash(account.password_hash, password):
                logger.warning(f"认证失败: 密码错误 - {username}", "AuthManager.authenticate_user")
                
                # 增加登录失败次数
                account.login_attempts += 1
                
                # 检查是否需要锁定账户
                if account.login_attempts >= self.config['max_login_attempts']:
                    account.locked_until = current_time + self.config['lockout_duration']
                    logger.warning(f"账户因多次登录失败被锁定: {username}, 锁定时间: {self.config['lockout_duration']}秒", "AuthManager.authenticate_user")
                    
                    return {
                        'success': False,
                        'message': f'密码错误次数过多，账户已被锁定{self.config["lockout_duration"]}秒',
                        'error_code': 'ACCOUNT_LOCKED'
                    }
                
                return {
                    'success': False,
                    'message': f'用户名或密码错误，还可尝试{self.config["max_login_attempts"] - account.login_attempts}次',
                    'error_code': 'INVALID_CREDENTIALS'
                }
            
            # 认证成功，重置登录失败次数
            account.login_attempts = 0
            account.locked_until = 0
            account.last_login = current_time
            
            # 创建用户对象
            user = User(username, account)
            
            # 生成令牌信息
            token_id = secrets.token_hex(16)
            token_data = {
                'token_id': token_id,
                'created_at': current_time,
                'expires_at': current_time + self.config['session_timeout'],
                'last_activity': current_time,
                'ip_address': request.remote_addr,
                'user_agent': request.user_agent.string
            }
            
            # 存储令牌信息（支持多会话并发登录）
            if username not in self.user_tokens:
                self.user_tokens[username] = {}

            # 将本次登录生成的令牌保存到对应的 token_id 键下
            self.user_tokens[username][token_id] = token_data
            # 同步反向映射
            self.token_to_user[token_id] = username
            
            # 使用Flask-Login登录用户
            login_user(user, remember=True, duration=timedelta(seconds=self.config['session_timeout']))
            
            # 在会话中存储令牌ID
            session['token_id'] = token_id
            session['token_created_at'] = current_time
            session.permanent = True
            
            logger.info(f"用户认证成功: {username}, 令牌ID: {token_id[:8]}...", "AuthManager.authenticate_user")
            
            account = self.accounts.get(username)
            return {
                'success': True,
                'message': '登录成功',
                'token': token_id,
                'user': {
                    'username': username,
                    'permissions': account.permissions if account else [],
                    'last_login': account.last_login if account else None,
                    'is_active': account.is_active if account else True,
                    'token_expires_at': token_data['expires_at']
                }
            }
            
        except Exception as e:
            logger.error(f"用户认证过程发生异常: {username}", "AuthManager.authenticate_user", e)
            return {
                'success': False,
                'message': '认证过程发生错误',
                'error_code': 'AUTHENTICATION_ERROR'
            }
    
    def logout_user_session(self) -> Dict[str, any]:
        """注销用户会话"""
        logger.info(f"用户注销: {current_user.username if current_user.is_authenticated else '未知用户'}", "AuthManager.logout_user_session")
        
        try:
            # 获取当前用户名用于日志
            username = current_user.username if current_user.is_authenticated else '未知用户'
            
            # 清除当前会话对应的令牌，而不是移除所有会话，避免误杀其他在线客户端
            token_id = session.get('token_id')
            if username in self.user_tokens and token_id:
                token_dict = self.user_tokens[username]
                if token_id in token_dict:
                    del token_dict[token_id]
                    # 同步删除反向映射
                    self.token_to_user.pop(token_id, None)
                    logger.debug(f"已清除当前会话令牌: {username}, 令牌ID: {token_id[:8]}...", "AuthManager.logout_user_session")
                # 如果该用户已无其它令牌，移除空字典
                if not token_dict:
                    del self.user_tokens[username]
            
            # 使用Flask-Login注销用户
            logout_user()
            
            # 清除会话数据
            session.clear()
            
            logger.info(f"用户注销成功: {username}", "AuthManager.logout_user_session")
            
            return {
                'success': True,
                'message': '注销成功'
            }
            
        except Exception as e:
            logger.error("用户注销过程发生异常", "AuthManager.logout_user_session", e)
            return {
                'success': False,
                'message': '注销过程发生错误'
            }
    
    def verify_current_user(self) -> Dict[str, any]:
        """验证当前用户"""
        logger.debug("验证当前用户", "AuthManager.verify_current_user")
        
        try:
            # 检查用户是否已认证
            if not current_user.is_authenticated:
                logger.debug("用户未认证", "AuthManager.verify_current_user")
                return {
                    'success': False,
                    'message': '用户未认证',
                    'error_code': 'NOT_AUTHENTICATED'
                }
            
            username = current_user.username
            current_time = time.time()
            
            # 令牌字典：token_id -> token_data
            token_dict = self.user_tokens.get(username)
            if not token_dict:
                logger.warning(f"令牌验证失败: 未找到任何令牌 - {username}", "AuthManager.verify_current_user")
                return {
                    'success': False,
                    'message': '会话已过期，请重新登录',
                    'error_code': 'TOKEN_NOT_FOUND'
                }

            # 从会话中取得 token_id 并尝试获取对应令牌数据
            session_token_id = session.get('token_id')
            token_data = token_dict.get(session_token_id)

            if not session_token_id or not token_data:
                logger.warning(f"令牌验证失败: 令牌ID不匹配 - {username}", "AuthManager.verify_current_user")
                return {
                    'success': False,
                    'message': '会话已在其他设备登录，请重新登录',
                    'error_code': 'TOKEN_MISMATCH'
                }
            
            # 检查令牌是否过期
            if token_data['expires_at'] < current_time:
                # 令牌已过期，但在刷新窗口期内可以自动刷新
                if current_time - token_data['expires_at'] <= self.config['token_refresh_window']:
                    # 自动刷新令牌
                    token_data['expires_at'] = current_time + self.config['session_timeout']
                    token_data['last_activity'] = current_time
                    
                    # 更新Flask-Login会话
                    login_user(current_user, remember=True, duration=timedelta(seconds=self.config['session_timeout']))
                    
                    logger.info(f"令牌已自动刷新: {username}, 新过期时间: {token_data['expires_at']}", "AuthManager.verify_current_user")
                else:
                    # 超出刷新窗口期，令牌失效
                    logger.warning(f"令牌验证失败: 令牌已过期且超出刷新窗口期 - {username}", "AuthManager.verify_current_user")
                    return {
                        'success': False,
                        'message': '会话已过期，请重新登录',
                        'error_code': 'TOKEN_EXPIRED'
                    }
            
            # 更新令牌最后活动时间
            token_data['last_activity'] = current_time
            
            # 如果令牌即将过期（小于剩余时间的20%），则自动延长
            remaining_time = token_data['expires_at'] - current_time
            if remaining_time < self.config['session_timeout'] * 0.2:
                token_data['expires_at'] = current_time + self.config['session_timeout']
                logger.debug(f"令牌即将过期，已自动延长: {username}", "AuthManager.verify_current_user")
            
            logger.debug(f"当前用户验证成功: {username}", "AuthManager.verify_current_user")
            
            account = self.accounts.get(username)
            return {
                'success': True,
                'user': {
                    'username': username,
                    'permissions': account.permissions if account else [],
                    'last_login': account.last_login if account else None,
                    'is_active': account.is_active if account else True,
                    'token_expires_at': token_data['expires_at']
                }
            }
            
        except Exception as e:
            logger.error("验证当前用户过程发生异常", "AuthManager.verify_current_user", e)
            return {
                'success': False,
                'message': '验证过程发生错误',
                'error_code': 'VERIFICATION_ERROR'
            }
    
    def check_user_permission(self, permission: str) -> bool:
        """检查当前用户权限"""
        logger.debug(f"检查用户权限: {permission}", "AuthManager.check_user_permission")
        
        try:
            # 检查用户是否已认证
            if not current_user.is_authenticated:
                logger.debug(f"用户未认证，权限检查失败: {permission}", "AuthManager.check_user_permission")
                return False
            
            # 检查用户权限
            has_permission = current_user.has_permission(permission)
            
            logger.debug(f"用户权限检查结果: {current_user.username}, 权限: {permission}, 结果: {has_permission}", "AuthManager.check_user_permission")
            
            return has_permission
            
        except Exception as e:
            logger.error(f"检查用户权限过程发生异常: {permission}", "AuthManager.check_user_permission", e)
            return False
    
    def login_user(self, username: str, password: str) -> Dict[str, any]:
        """用户登录（兼容性方法）"""
        logger.debug(f"调用登录用户方法: {username}", "AuthManager.login_user")
        return self.authenticate_user(username, password)
    
    def logout_user(self) -> Dict[str, any]:
        """用户注销（兼容性方法）"""
        logger.debug("调用注销用户方法", "AuthManager.logout_user")
        return self.logout_user_session()
    
    def get_current_user_info(self) -> Dict[str, any]:
        """获取当前用户信息"""
        logger.debug("获取当前用户信息", "AuthManager.get_current_user_info")
        
        try:
            # 检查用户是否已认证
            if not current_user.is_authenticated:
                logger.debug("用户未认证", "AuthManager.get_current_user_info")
                return {}
            
            user_info = {
                'username': current_user.username,
                'permissions': current_user.account.permissions,
                'last_login': current_user.account.last_login,
                'is_active': current_user.account.is_active
            }
            
            logger.debug(f"获取用户信息成功: {current_user.username}", "AuthManager.get_current_user_info")
            return user_info
            
        except Exception as e:
            logger.error("获取当前用户信息发生异常", "AuthManager.get_current_user_info", e)
            return {}
    
    def init_app(self, app):
        """初始化Flask应用"""
        logger.info("初始化Flask应用认证", "AuthManager.init_app")
        
        from flask_login import LoginManager
        
        # 创建LoginManager实例
        login_manager = LoginManager()
        login_manager.init_app(app)
        
        # 设置用户加载器
        login_manager.user_loader(user_loader)
        
        # 设置登录视图
        login_manager.login_view = 'login'
        login_manager.login_message = '请先登录'
        
        logger.info("Flask应用认证初始化完成", "AuthManager.init_app")

    # -----------------------------------------------------------------
    # 基于 token_id 的直接验证（供 Header 调用，隔离不同客户端会话）
    # -----------------------------------------------------------------
    def verify_token_id(self, token_id: str) -> Dict[str, any]:
        """根据 token_id 直接验证用户，无需依赖 Cookie / Session。

        返回结构与 verify_current_user 一致，方便统一处理。"""

        logger.debug(
            f"根据 token 验证用户, token={str(token_id)[:8]}...",
            "AuthManager.verify_token_id",
        )

        if not token_id:
            return {
                'success': False,
                'message': '缺少令牌',
                'error_code': 'TOKEN_REQUIRED'
            }

        # 快速反向查找用户名
        username = self.token_to_user.get(token_id)
        if not username:
            logger.warning("未知令牌", "AuthManager.verify_token_id")
            return {
                'success': False,
                'message': '令牌无效或已过期',
                'error_code': 'TOKEN_INVALID'
            }

        token_dict = self.user_tokens.get(username, {})
        token_data = token_dict.get(token_id)
        if not token_data:
            logger.warning("令牌数据缺失", "AuthManager.verify_token_id")
            return {
                'success': False,
                'message': '令牌无效或已过期',
                'error_code': 'TOKEN_INVALID'
            }

        # 在当前请求上下文内直接注入用户对象，避免写入 Flask-Session
        try:
            from flask_login import _request_ctx_stack
            user = self.get_user(username)
            if user:
                _ctx = _request_ctx_stack.top
                if _ctx is not None:
                    _ctx.user = user
        except Exception as e:
            logger.debug(f"手动注入用户失败: {e}", "AuthManager.verify_token_id")

        # 直接返回验证成功信息（已在上面检查过期/续期）
        account = self.accounts.get(username)
        return {
            'success': True,
            'user': {
                'username': username,
                'permissions': account.permissions if account else [],
                'last_login': account.last_login if account else None,
                'is_active': account.is_active if account else True,
                'token_expires_at': token_data['expires_at']
            }
        }

# 全局认证管理器实例
auth_manager = AuthManager()

def get_auth_manager() -> AuthManager:
    """获取认证管理器实例"""
    logger.debug("获取认证管理器实例", "get_auth_manager")
    return auth_manager

def user_loader(username: str) -> Optional[User]:
    """用户加载器（Flask-Login要求）"""
    logger.debug(f"加载用户: {username}", "user_loader")
    return auth_manager.get_user(username)

def require_permission(permission: str):
    """权限验证装饰器"""
    def decorator(f):
        def decorated_function(*args, **kwargs):
            logger.debug(f"验证权限: {permission}", "require_permission")
            
            # 检查用户是否已登录
            if not current_user.is_authenticated:
                logger.warning(f"权限验证失败: 用户未登录 - {permission}", "require_permission")
                return jsonify({
                    'success': False,
                    'message': '需要登录',
                    'error_code': 'LOGIN_REQUIRED'
                }), 401
            
            # 检查用户权限
            if not auth_manager.check_user_permission(permission):
                logger.warning(f"权限验证失败: 用户无权限 - {current_user.username}, 权限: {permission}", "require_permission")
                return jsonify({
                    'success': False,
                    'message': '权限不足',
                    'error_code': 'PERMISSION_DENIED'
                }), 403
            
            logger.debug(f"权限验证成功: {current_user.username}, 权限: {permission}", "require_permission")
            return f(*args, **kwargs)
        
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

def api_login_required(f):
    """API登录验证装饰器"""
    def decorated_function(*args, **kwargs):
        logger.debug("API登录验证", "api_login_required")
        
        # 检查用户是否已登录
        if not current_user.is_authenticated:
            logger.warning("API访问失败: 用户未登录", "api_login_required")
            return jsonify({
                'success': False,
                'message': '需要登录',
                'error_code': 'LOGIN_REQUIRED'
            }), 401
        
        logger.debug(f"API登录验证成功: {current_user.username}", "api_login_required")
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """管理员权限验证装饰器"""
    def decorated_function(*args, **kwargs):
        logger.debug("管理员权限验证", "admin_required")
        
        # 检查用户是否已登录
        if not current_user.is_authenticated:
            logger.warning("管理员操作失败: 用户未登录", "admin_required")
            return jsonify({
                'success': False,
                'message': '需要登录',
                'error_code': 'LOGIN_REQUIRED'
            }), 401
        
        # 检查用户是否有管理员权限
        if not ('admin' in current_user.account.permissions or 'all' in current_user.account.permissions):
            logger.warning(f"管理员操作失败: 用户权限不足 - {current_user.username}", "admin_required")
            return jsonify({
                'success': False,
                'message': '需要管理员权限',
                'error_code': 'ADMIN_REQUIRED'
            }), 403
        
        logger.debug(f"管理员权限验证成功: {current_user.username}", "admin_required")
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

def get_current_user_info() -> Dict[str, any]:
    """获取当前用户信息的全局函数"""
    logger.debug("调用全局获取当前用户信息函数", "get_current_user_info")
    return auth_manager.get_current_user_info() 