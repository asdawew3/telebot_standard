#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
客户端Web应用模块
提供Web界面，支持用户登录、实例管理和控制台交互
"""

import os
import sys
import json
import uuid
import time
import logging
import threading
import traceback
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from flask_socketio import SocketIO, emit, disconnect
from flask_session import Session

from .client_logger import get_client_logger, log_debug, log_info, log_error, log_warning, log_operation
from .client_api import ClientAPI
from .console_manager import ConsoleManager

# 获取日志实例（启动时清空日志文件）
logger = get_client_logger(clear_on_start=True)

# 全局变量
client_api = None
console_manager = None
socketio = None
session_manager = None


class SessionManager:
    """会话管理器，负责处理会话的存储和验证"""

    def __init__(self, app=None):
        """
        初始化会话管理器

        Args:
            app: Flask应用实例
        """
        logger.debug("初始化会话管理器", "SessionManager.__init__")

        # 设置默认配置
        self.config = {
            'default_expiry': 86400,  # 默认会话有效期（1天，单位：秒）
            'long_expiry': 86400 * 90,  # 长期会话有效期（90天，单位：秒）
            'refresh_threshold': 3600,  # 会话刷新阈值（1小时，单位：秒）
        }

        # 初始化属性
        self.app = None
        self.last_login_response = None  # 保存最近一次登录响应

        # 如果提供了应用实例，立即初始化
        if app:
            self.init_app(app)

        logger.info("会话管理器初始化完成", "SessionManager.__init__")

    def init_app(self, app):
        """
        初始化Flask应用

        Args:
            app: Flask应用实例
        """
        logger.debug("初始化会话管理器与Flask应用", "SessionManager.init_app")

        # 确保会话目录存在
        session_dir = app.config.get('SESSION_FILE_DIR', 'flask_session')
        os.makedirs(session_dir, exist_ok=True)

        # 记录会话配置
        logger.debug(f"会话配置: 类型={app.config.get('SESSION_TYPE')}, "
                     f"持久化={app.config.get('SESSION_PERMANENT')}, "
                     f"有效期={app.config.get('PERMANENT_SESSION_LIFETIME')}秒",
                     "SessionManager.init_app")

        # 检查现有会话文件
        try:
            session_files = [f for f in os.listdir(session_dir)
                             if os.path.isfile(os.path.join(session_dir, f))]
            logger.debug(
                f"现有会话文件数量: {len(session_files)}", "SessionManager.init_app")
        except Exception as e:
            logger.warning(f"检查会话文件异常: {e}", "SessionManager.init_app")

    def set_session(self, username: str, user_info: Dict, remember: bool = False) -> None:
        """
        设置会话数据

        Args:
            username: 用户名
            user_info: 用户信息
            remember: 是否记住登录状态
        """
        logger.debug(
            f"设置会话数据: 用户={username}, remember={remember}", "SessionManager.set_session")

        # 清除之前的会话数据
        session.clear()

        # 设置基本会话数据
        session['logged_in'] = True
        session['username'] = username
        session['user_info'] = user_info
        session['remember'] = remember

        # 确保会话是永久的
        session.permanent = True

        # 获取令牌 - 从多个可能的来源尝试获取
        auth_token = None

        # 1. 直接从全局API客户端获取令牌
        global client_api
        if client_api and client_api.current_token:
            auth_token = client_api.current_token
            logger.debug(
                f"从API客户端获取令牌，长度={len(auth_token)}", "SessionManager.set_session")

        # 2. 如果上面没有找到，尝试从用户信息中获取
        if not auth_token:
            # 尝试从user_info中获取token
            if isinstance(user_info, dict):
                if 'token' in user_info:
                    auth_token = user_info['token']
                    logger.debug(
                        f"从用户信息中获取令牌，长度={len(auth_token)}", "SessionManager.set_session")

        # 3. 最后一种情况，检查是否有登录响应
        if not auth_token and hasattr(self, 'last_login_response') and isinstance(self.last_login_response, dict):
            auth_token = self.last_login_response.get('token')
            if auth_token:
                logger.debug(
                    f"从上次登录响应中获取令牌，长度={len(auth_token)}", "SessionManager.set_session")

        # 保存令牌到会话
        if auth_token:
            logger.debug(
                f"保存认证令牌到会话，长度={len(auth_token)}", "SessionManager.set_session")
            session['auth_token'] = auth_token
        else:
            logger.error("无法获取认证令牌，会话将无效", "SessionManager.set_session")

        # 设置当前时间
        current_time = time.time()
        session['login_time'] = current_time
        session['last_activity'] = current_time

        # 设置令牌过期时间
        if remember:
            # 长期会话 (90天)
            expiry_seconds = self.config['long_expiry']
            logger.debug(
                f"设置长期会话，过期时间={expiry_seconds/86400:.1f}天", "SessionManager.set_session")
        else:
            # 标准会话 (24小时)
            expiry_seconds = self.config['default_expiry']
            logger.debug(
                f"设置标准会话，过期时间={expiry_seconds/3600:.1f}小时", "SessionManager.set_session")

        token_expiry = current_time + expiry_seconds
        session['token_expiry'] = token_expiry

        # 确保会话被保存
        session.modified = True

        # 记录会话详情
        logger.debug(f"会话数据已设置: logged_in={session.get('logged_in')}, username={session.get('username')}, " +
                     f"token_expiry={session.get('token_expiry')}, has_token={session.get('auth_token') is not None}, " +
                     f"token_length={len(session.get('auth_token', ''))} 字符", "SessionManager.set_session")

        # 记录操作日志
        logger.operation("会话数据已设置", "SessionManager.set_session", {
            'username': username,
            'remember': remember,
            'has_token': auth_token is not None,
            'token_length': len(auth_token) if auth_token else 0,
            'expiry': token_expiry
        })

    def verify_session(self) -> bool:
        """
        验证会话是否有效

        Returns:
            bool: 会话是否有效
        """
        logger.debug("验证会话状态", "SessionManager.verify_session")

        # 检查基本会话状态
        if not session:
            logger.warning("会话对象不存在", "SessionManager.verify_session")
            return False

        # 检查登录状态
        logged_in = session.get('logged_in', False)
        if not logged_in:
            logger.warning("会话未登录", "SessionManager.verify_session")
            return False

        # 检查用户名
        username = session.get('username')
        if not username:
            logger.warning("会话中缺少用户名", "SessionManager.verify_session")
            return False

        # 检查认证令牌
        auth_token = session.get('auth_token')
        if not auth_token:
            logger.warning("会话中缺少认证令牌", "SessionManager.verify_session")
            return False

        # 验证令牌格式
        if not isinstance(auth_token, str):
            logger.warning(
                f"令牌格式错误: 类型={type(auth_token).__name__}", "SessionManager.verify_session")
            return False

        # 验证令牌长度
        if len(auth_token) < 32:  # 假设有效令牌至少32字符
            logger.warning(
                f"令牌长度不足: 长度={len(auth_token)}", "SessionManager.verify_session")
            return False

        # 检查令牌过期时间
        token_expiry = session.get('token_expiry', 0)
        current_time = time.time()

        if not token_expiry:
            logger.warning("会话中缺少令牌过期时间", "SessionManager.verify_session")
            return False

        if current_time >= token_expiry:
            # 计算过期时间差
            expired_seconds = current_time - token_expiry
            logger.warning(
                f"会话令牌已过期: 过期时间={token_expiry}, 当前时间={current_time}, 已过期{expired_seconds:.1f}秒", "SessionManager.verify_session")
            return False

        # 计算剩余有效时间
        remaining_time = token_expiry - current_time
        remaining_hours = remaining_time / 3600

        # 会话有效
        logger.debug(
            f"会话验证成功，用户={username}, 令牌长度={len(auth_token)}, 剩余有效期={remaining_hours:.2f}小时", "SessionManager.verify_session")
        return True

    def clear_session(self) -> None:
        """清除会话数据"""
        logger.debug("清除会话数据", "SessionManager.clear_session")

        # 记录当前用户名
        username = session.get('username', '未知')

        # 清除会话
        session.clear()

        logger.info(f"会话已清除，用户={username}", "SessionManager.clear_session")


def create_app(server_url: str = 'http://127.0.0.1:5000') -> Flask:
    """
    创建Flask应用实例

    Args:
        server_url: 服务器地址

    Returns:
        Flask应用实例
    """
    logger.info("创建客户端Web应用", "create_app")
    logger.debug(f"服务器地址: {server_url}", "create_app")

    # 创建Flask应用
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')

    # 配置Flask
    # 固定密钥，避免重启后会话失效
    app.config['SECRET_KEY'] = 'telebot_client_secret_key_2024'
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = True  # 设置为持久会话
    app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 90  # 会话有效期延长到90天（秒）
    app.config['SESSION_USE_SIGNER'] = True  # 使用签名保护会话数据
    app.config['SESSION_FILE_DIR'] = 'flask_session'
    app.config['SESSION_FILE_THRESHOLD'] = 500  # 最多保存500个会话文件
    app.config['SESSION_KEY_PREFIX'] = 'telebot_client_'  # 会话文件前缀
    # 自定义会话Cookie名称
    app.config['SESSION_COOKIE_NAME'] = 'telebot_client_session'
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # 防止XSS
    app.config['SESSION_COOKIE_SECURE'] = False   # 本地HTTP环境关闭Secure
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # 跨站点时发送Cookie策略
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True  # 每次请求自动刷新过期时间
    app.config['SESSION_FILE_MODE'] = 0o600  # 设置会话文件权限
    app.config['SESSION_COOKIE_PATH'] = '/'  # 确保Cookie在整个应用中可用

    # 输出会话配置日志
    logger.debug(f"会话相关配置: COOKIE_NAME={app.config.get('SESSION_COOKIE_NAME')}, "
                 f"SAMESITE={app.config['SESSION_COOKIE_SAMESITE']}, "
                 f"PERMANENT_LIFETIME={app.config['PERMANENT_SESSION_LIFETIME']}秒", "create_app")

    # 确保会话目录存在
    os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

    # 初始化Flask-Session
    Session(app)
    logger.debug("Flask-Session已初始化", "create_app")

    # 初始化会话管理器
    global session_manager
    session_manager = SessionManager(app)
    logger.debug("会话管理器已初始化", "create_app")

    # 启用CORS
    CORS(app, supports_credentials=True)

    # 初始化全局变量
    global client_api, console_manager, socketio

    # 创建API客户端
    client_api = ClientAPI(server_url=server_url)
    logger.debug("API客户端已创建", "create_app")

    # 创建控制台管理器
    console_manager = ConsoleManager(client_api)
    logger.debug("控制台管理器已创建", "create_app")

    # 创建SocketIO实例
    socketio = SocketIO(app,
                        cors_allowed_origins="*",
                        async_mode='threading',
                        manage_session=False)
    logger.debug(
        "SocketIO已创建，配置: async_mode=threading, manage_session=False", "create_app")

    # 设置控制台回调
    console_manager.on_output = console_output_handler
    console_manager.on_error = console_error_handler
    console_manager.on_status_change = console_status_change_handler
    logger.debug("控制台回调已设置", "create_app")

    # 注册路由
    register_routes(app)
    logger.debug("路由已注册", "create_app")

    # 注册SocketIO事件
    register_socketio_events(socketio)
    logger.debug("SocketIO事件已注册", "create_app")

    logger.info("客户端Web应用创建完成", "create_app")
    return app


def verify_session_token() -> bool:
    """验证会话令牌是否有效"""
    logger.debug("验证会话令牌", "verify_session_token")

    # 使用会话管理器验证
    global session_manager
    if session_manager:
        # 添加详细日志
        auth_token = session.get('auth_token', None)
        token_status = "存在" if auth_token else "不存在"
        token_length = len(auth_token) if auth_token else 0
        token_expiry = session.get('token_expiry', 0)
        current_time = time.time()

        if token_expiry:
            remaining_time = token_expiry - current_time
            expiry_status = f"剩余 {remaining_time/3600:.2f}小时" if remaining_time > 0 else f"已过期 {-remaining_time:.1f}秒"
            logger.debug(
                f"当前会话令牌: {token_status}, 长度: {token_length}, 过期状态: {expiry_status}", "verify_session_token")
        else:
            logger.debug(
                f"当前会话令牌: {token_status}, 长度: {token_length}, 无过期时间", "verify_session_token")

        # 调用会话管理器验证
        result = session_manager.verify_session()
        logger.debug(f"会话管理器验证结果: {result}", "verify_session_token")
        return result

    # 备用验证方法（如果会话管理器不可用）
    logged_in = session.get('logged_in', False)
    token_expiry = session.get('token_expiry', 0)
    auth_token = session.get('auth_token', None)
    current_time = time.time()

    # 记录会话状态
    logger.debug(f"会话状态: logged_in={logged_in}, expiry={token_expiry}, now={current_time}, " +
                 f"auth_token={'存在' if auth_token else '不存在'}, 长度={len(auth_token) if auth_token else 0}", "verify_session_token")

    # 验证基本条件
    if not logged_in or not token_expiry:
        logger.warning("会话无效: 未登录或无过期时间", "verify_session_token")
        return False

    # 验证令牌存在
    if not auth_token:
        logger.warning("会话无效: 缺少认证令牌", "verify_session_token")
        return False

    # 验证令牌格式
    if not isinstance(auth_token, str) or len(auth_token) < 32:
        logger.warning(
            f"会话无效: 令牌格式错误或长度不足 ({len(auth_token)})", "verify_session_token")
        return False

    # 验证过期时间
    if current_time >= token_expiry:
        expired_seconds = current_time - token_expiry
        logger.warning(
            f"会话已过期: {expired_seconds:.1f}秒前 (expiry={token_expiry}, now={current_time})", "verify_session_token")
        return False

    # 计算剩余有效时间
    remaining_time = token_expiry - current_time
    remaining_hours = remaining_time / 3600

    # 验证通过
    logger.debug(
        f"会话令牌验证通过，剩余有效期: {remaining_hours:.2f}小时", "verify_session_token")
    return True


def register_routes(app: Flask) -> None:
    """
    注册路由

    Args:
        app: Flask应用实例
    """
    logger.debug("开始注册路由", "register_routes")

    @app.before_request
    def before_request():
        """每个请求前执行的函数，增加详细会话日志"""
        # 记录请求基础信息
        logger.debug(
            f"收到请求: {request.method} {request.path}", "before_request")

        # 记录当前会话摘要
        try:
            session_id = session.sid if hasattr(session, 'sid') else 'unknown'
            session_keys = list(session.keys())
            logger.debug(
                f"当前会话ID={session_id}, Keys={session_keys}", "before_request")

            # 检查会话持久性
            if not session.permanent and len(session_keys) > 0:
                logger.warning("会话未设置为永久，可能导致会话丢失，正在修复", "before_request")
                session.permanent = True
                session.modified = True
                logger.debug("已将会话设置为永久", "before_request")

            # 添加更详细的会话信息日志
            if 'username' in session:
                username = session.get('username')
                logged_in = session.get('logged_in', False)
                token_expiry = session.get('token_expiry', 0)
                current_time = time.time()
                auth_token = session.get('auth_token')

                # 计算剩余时间（如果有过期时间）
                if token_expiry:
                    remaining_time = token_expiry - current_time
                    remaining_hours = remaining_time / 3600
                    expiry_status = f"剩余 {remaining_hours:.2f}小时" if remaining_time > 0 else "已过期"
                    logger.debug(
                        f"会话详情: 用户={username}, 登录状态={logged_in}, 令牌存在={auth_token is not None}, 令牌长度={len(auth_token) if auth_token else 0}, 过期状态={expiry_status}", "before_request")
                else:
                    logger.debug(
                        f"会话详情: 用户={username}, 登录状态={logged_in}, 令牌存在={auth_token is not None}, 令牌长度={len(auth_token) if auth_token else 0}, 无过期时间", "before_request")
        except Exception as e:
            logger.debug(f"获取会话信息异常: {str(e)}", "before_request")

        # 跳过登录相关路由和静态文件
        if request.endpoint in ['login', 'static'] or request.path.startswith('/static/'):
            return

        # 跳过WebSocket连接请求
        if request.path.startswith('/socket.io/'):
            return

        # 使用会话管理器验证会话
        if not verify_session_token():
            # 记录详细的会话状态
            logged_in = session.get('logged_in', False)
            username = session.get('username', '未知')
            auth_token = session.get('auth_token')
            token_expiry = session.get('token_expiry', 0)
            current_time = time.time()

            # 记录会话验证失败的详细原因
            if not logged_in:
                logger.warning(
                    f"会话验证失败: 未登录状态, 用户={username}", "before_request")
            elif not auth_token:
                logger.warning(
                    f"会话验证失败: 缺少令牌, 用户={username}, 登录状态={logged_in}", "before_request")
            elif token_expiry and current_time >= token_expiry:
                expired_seconds = current_time - token_expiry
                logger.warning(
                    f"会话验证失败: 令牌已过期 {expired_seconds:.1f}秒, 用户={username}", "before_request")
            else:
                logger.warning(
                    f"会话验证失败: 未知原因, 用户={username}, 令牌存在={auth_token is not None}, 过期时间={token_expiry}", "before_request")

            logger.warning("会话验证失败，重定向到登录", "before_request")
            if request.path.startswith('/api/'):
                return jsonify({'success': False, 'message': '会话已过期，请重新登录', 'error_code': 'SESSION_EXPIRED'}), 401
            return redirect(url_for('login'))

    @app.route('/')
    def index():
        """首页"""
        logger.debug("访问首页", "index")
        return render_template('client_index.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """登录页面和处理"""
        logger.debug(f"访问登录页面: method={request.method}", "login")

        # 已登录用户重定向到首页
        if verify_session_token():
            logger.debug("用户已登录，重定向到首页", "login")
            return redirect(url_for('index'))

        # 处理登录表单提交
        if request.method == 'POST':
            logger.debug("处理登录表单提交", "login")

            # 获取表单数据
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            remember = request.form.get('remember', 'off') == 'on'

            logger.debug(
                f"登录表单数据: username={username}, remember={remember}", "login")

            # 基本验证
            if not username:
                logger.warning("登录失败: 用户名为空", "login")
                flash('请输入用户名', 'danger')
                return render_template('client_login.html')

            if not password:
                logger.warning("登录失败: 密码为空", "login")
                flash('请输入密码', 'danger')
                return render_template('client_login.html')

            try:
                # 获取API客户端
                global client_api
                if not client_api:
                    logger.error("API客户端未初始化", "login")
                    flash('系统错误: API客户端未初始化', 'danger')
                    return render_template('client_login.html')

                # 发送登录请求
                logger.info(f"尝试登录用户: {username}", "login")
                result = client_api.login(username, password)

                # 处理登录结果
                if result.get('success'):
                    # 获取用户信息和令牌
                    user_info = result.get('user', {})
                    auth_token = result.get('token')

                    # 验证令牌存在
                    if not auth_token:
                        logger.error("登录成功但服务器未返回令牌", "login")
                        flash('登录失败: 服务器未返回认证令牌', 'danger')
                        return render_template('client_login.html')

                    # 记录令牌信息
                    logger.debug(f"获取到认证令牌，长度={len(auth_token)}", "login")

                    # 使用会话管理器保存会话
                    global session_manager
                    if session_manager:
                        logger.debug("使用会话管理器保存会话", "login")
                        # 保存登录响应以便会话管理器可以获取令牌
                        session_manager.last_login_response = result
                        # 确保用户信息中包含令牌
                        if 'token' not in user_info and auth_token:
                            user_info['token'] = auth_token
                        session_manager.set_session(
                            username, user_info, remember)
                    else:
                        # 备用方法保存会话
                        logger.warning("会话管理器不可用，使用备用方法保存会话", "login")

                        # 设置会话数据
                        session['logged_in'] = True
                        session['username'] = username
                        session['user_info'] = user_info
                        session['remember'] = remember
                        session['auth_token'] = auth_token

                        # 设置令牌过期时间
                        if remember:
                            # 长期会话 (90天)
                            expiry_seconds = 86400 * 90
                        else:
                            # 标准会话 (24小时)
                            expiry_seconds = 86400

                        token_expiry = time.time() + expiry_seconds
                        session['token_expiry'] = token_expiry

                        # 确保会话是永久的
                        session.permanent = True

                        logger.debug(
                            f"会话数据已设置: expiry={token_expiry}, remember={remember}", "login")

                    # 确保客户端API实例也保存了令牌
                    client_api.current_token = auth_token
                    client_api.is_authenticated = True
                    client_api.current_user = user_info
                    logger.debug("已更新API客户端认证状态", "login")

                    # 记录登录成功
                    logger.info(f"用户登录成功: {username}", "login")
                    logger.operation("用户登录成功", "login", {
                        'username': username,
                        'remember': remember,
                        'token_length': len(auth_token)
                    })

                    # 重定向到首页
                    flash(f'欢迎回来, {username}!', 'success')
                    return redirect(url_for('index'))

                else:
                    # 登录失败
                    error_message = result.get('message', '登录失败')
                    error_code = result.get('error_code', 'UNKNOWN_ERROR')

                    logger.warning(
                        f"用户登录失败: {username}, 错误: {error_message}, 代码: {error_code}", "login")
                    logger.operation("用户登录失败", "login", {
                        'username': username,
                        'error': error_message,
                        'error_code': error_code
                    })

                    flash(f'登录失败: {error_message}', 'danger')
                    return render_template('client_login.html')

            except Exception as e:
                # 处理异常
                logger.error("登录过程发生异常", "login", e)
                logger.debug(f"异常详情: {str(e)}", "login")

                flash(f'登录过程发生错误: {str(e)}', 'danger')
                return render_template('client_login.html')

        # GET请求，显示登录页面
        return render_template('client_login.html')

    @app.route('/logout')
    def logout():
        """登出"""
        logger.debug("用户请求登出", "logout")

        # 记录当前用户名
        username = session.get('username', '未知')

        try:
            # 调用API登出
            if client_api:
                # 确保使用会话中保存的令牌进行请求
                auth_token = session.get('auth_token')
                if auth_token:
                    logger.debug(f"使用会话令牌登出: {auth_token[:8]}...", "logout")
                    # 将令牌添加到请求头
                    client_api.session.headers['X-Auth-Token'] = auth_token

                result = client_api.logout()
                logger.debug(
                    f"API登出结果: {result.get('success', False)}", "logout")

                # 清除请求头中的令牌
                if 'X-Auth-Token' in client_api.session.headers:
                    del client_api.session.headers['X-Auth-Token']

            # 使用会话管理器清除会话
            global session_manager
            if session_manager:
                logger.debug("使用会话管理器清除会话", "logout")
                session_manager.clear_session()
            else:
                # 传统方式清除会话
                logger.debug("使用传统方式清除会话", "logout")
                session.clear()

            # 记录操作
            logger.info(f"用户 {username} 已登出", "logout")
            logger.operation("用户登出", "logout", {'username': username})

            # 重定向到登录页面
            return redirect(url_for('login'))

        except Exception as e:
            logger.error("登出过程发生异常", "logout", e)

            # 即使发生异常，也清除会话
            if session_manager:
                session_manager.clear_session()
            else:
                session.clear()

            # 重定向到登录页面
            return redirect(url_for('login'))

    @app.route('/api/instances')
    def api_instances():
        """获取实例列表API"""
        logger.debug("获取实例列表", "api_instances")

        # 获取分组参数
        group_id = request.args.get('group_id')

        # 确保使用会话中保存的令牌进行请求
        auth_token = session.get('auth_token')
        if auth_token:
            logger.debug(f"使用会话令牌请求实例列表: {auth_token[:8]}...", "api_instances")
            # 将令牌添加到请求头
            client_api.session.headers['X-Auth-Token'] = auth_token

        # 调用API获取实例列表
        result = client_api.list_instances(group_id)

        # 清除请求头中的令牌
        if 'X-Auth-Token' in client_api.session.headers:
            del client_api.session.headers['X-Auth-Token']

        # 记录获取结果
        if result.get('success'):
            logger.info(
                f"获取到 {len(result.get('instances', []))} 个实例", "api_instances")
        else:
            logger.warning(
                f"获取实例列表失败: {result.get('message')}", "api_instances")

        return jsonify(result)

    @app.route('/api/console/connect', methods=['POST'])
    def api_connect_console():
        """连接到控制台"""
        logger.debug("处理控制台连接请求", "api_connect_console")

        # 验证会话令牌
        logger.debug("验证会话令牌", "api_connect_console")
        if not verify_session_token():
            logger.warning("未验证的用户尝试连接控制台", "api_connect_console")
            return jsonify({
                'success': False,
                'message': '未授权的操作，请重新登录'
            }), 401

        logger.debug("会话令牌验证成功", "api_connect_console")

        # 获取实例ID
        instance_id = request.json.get('instance_id')
        logger.debug(f"请求参数: instance_id={instance_id}", "api_connect_console")

        if not instance_id:
            logger.warning("缺少实例ID参数", "api_connect_console")
            return jsonify({
                'success': False,
                'message': '缺少实例ID参数'
            }), 400

        try:
            # 获取控制台管理器
            global console_manager

            if not console_manager:
                logger.error("控制台管理器未初始化", "api_connect_console")
                return jsonify({
                    'success': False,
                    'message': '控制台管理器未初始化'
                }), 500

            # 记录控制台管理器当前状态
            logger.debug(
                f"控制台管理器状态: connected={console_manager.connected}, instance_id={console_manager.instance_id}", "api_connect_console")

            # 确保使用会话中保存的令牌进行请求
            auth_token = session.get('auth_token')
            if auth_token:
                token_length = len(auth_token) if auth_token else 0
                token_preview = auth_token[:8] + \
                    '...' if auth_token and len(auth_token) > 8 else 'None'
                logger.debug(
                    f"使用会话令牌连接控制台: {token_preview}, 长度={token_length}", "api_connect_console")

                # 检查会话中的用户信息
                username = session.get('username', 'unknown')
                user_id = session.get('user_id', 'unknown')
                logger.debug(
                    f"当前会话用户信息: username={username}, user_id={user_id}", "api_connect_console")

                # 设置请求头中的令牌
                client_api.session.headers['X-Auth-Token'] = auth_token
                logger.debug("已将令牌添加到请求头", "api_connect_console")
            else:
                logger.warning("会话中缺少认证令牌", "api_connect_console")
                return jsonify({
                    'success': False,
                    'message': '会话令牌缺失，请重新登录'
                }), 401

            # 连接到控制台
            logger.info(f"尝试连接到实例控制台: {instance_id}", "api_connect_console")

            # 记录连接前的控制台状态
            logger.debug(
                f"连接前控制台状态: connected={console_manager.connected}, instance_id={console_manager.instance_id}", "api_connect_console")

            # 执行连接
            result = console_manager.connect(instance_id)
            logger.debug(f"连接结果: {result}", "api_connect_console")

            # 清除请求头中的令牌
            if 'X-Auth-Token' in client_api.session.headers:
                del client_api.session.headers['X-Auth-Token']
                logger.debug("已从请求头中清除令牌", "api_connect_console")

            # 处理连接结果
            if result.get('success'):
                logger.info(f"控制台连接成功: {instance_id}", "api_connect_console")

                # 记录连接后的控制台状态
                logger.debug(
                    f"连接后控制台状态: connected={console_manager.connected}, instance_id={console_manager.instance_id}", "api_connect_console")

                # 记录操作日志
                logger.operation("控制台连接成功", "api_connect_console", {
                    'instance_id': instance_id,
                    'username': username,
                    'user_id': user_id
                })

                return jsonify({
                    'success': True,
                    'message': '控制台连接成功',
                    'instance_id': instance_id
                })
            else:
                error_message = result.get('message', '控制台连接失败')
                logger.warning(
                    f"控制台连接失败: {error_message}", "api_connect_console")

                # 记录连接失败后的控制台状态
                logger.debug(
                    f"连接失败后控制台状态: connected={console_manager.connected}, instance_id={console_manager.instance_id}", "api_connect_console")

                # 记录操作日志
                logger.operation("控制台连接失败", "api_connect_console", {
                    'instance_id': instance_id,
                    'error': error_message,
                    'username': username,
                    'user_id': user_id
                })

                return jsonify({
                    'success': False,
                    'message': error_message
                }), 400

        except Exception as e:
            logger.error("连接控制台时发生异常", "api_connect_console", e)
            logger.debug(f"异常详情: {str(e)}", "api_connect_console")
            logger.debug(f"异常堆栈: {traceback.format_exc()}",
                         "api_connect_console")

            # 清除请求头中的令牌
            if 'X-Auth-Token' in client_api.session.headers:
                del client_api.session.headers['X-Auth-Token']
                logger.debug("异常处理中已从请求头中清除令牌", "api_connect_console")

            # 记录操作日志
            logger.operation("控制台连接异常", "api_connect_console", {
                'instance_id': instance_id if 'instance_id' in locals() else '未知',
                'exception': str(e)
            })

            return jsonify({
                'success': False,
                'message': f'连接控制台时发生异常: {str(e)}'
            }), 500

    @app.route('/api/console/execute', methods=['POST'])
    def api_console_execute():
        """执行控制台命令"""
        logger.debug("处理控制台命令执行请求", "api_console_execute")

        # 验证会话令牌
        if not verify_session_token():
            logger.warning("未验证的用户尝试执行控制台命令", "api_console_execute")
            return jsonify({
                'success': False,
                'message': '未授权的操作，请重新登录'
            }), 401

        # 获取命令
        command = request.json.get('command')
        if not command:
            logger.warning("缺少命令参数", "api_console_execute")
            return jsonify({
                'success': False,
                'message': '缺少命令参数'
            }), 400

        try:
            # 获取控制台管理器
            global console_manager, client_api

            if not console_manager:
                logger.error("控制台管理器未初始化", "api_console_execute")
                return jsonify({
                    'success': False,
                    'message': '控制台管理器未初始化'
                }), 500

            # 记录执行的命令详情
            logger.info(f"执行控制台命令: {command}", "api_console_execute")

            # 检查是否是特殊函数调用
            if 'sendMessageWithPagination' in command:
                logger.debug(
                    f"检测到sendMessageWithPagination函数调用: {command}", "api_console_execute")

                # 检查令牌过期信息
                if client_api and client_api.current_token:
                    # 假设令牌有效期为24小时，计算剩余时间
                    token_expiry = session.get(
                        'token_expiry', time.time() + 86400)
                    remaining_time = token_expiry - time.time()
                    remaining_hours = remaining_time / 3600
                    expiry_time = time.strftime(
                        '%Y-%m-%d %H:%M:%S', time.localtime(token_expiry))

                    logger.debug(
                        f"令牌过期信息: 剩余时间={remaining_hours:.2f}小时, 过期时间={expiry_time}", "api_console_execute")

                # 尝试检查函数是否已正确注入
                if console_manager.connected and console_manager.instance_id:
                    logger.debug(
                        "尝试验证sendMessageWithPagination函数是否存在", "api_console_execute")

                    # 获取当前实例ID
                    instance_id = console_manager.instance_id

                    # 检查函数存在性
                    try:
                        check_result = client_api.execute_command(
                            instance_id,
                            'executeConsoleCommand',
                            ["typeof sendMessageWithPagination"]
                        )

                        if check_result.get('success'):
                            function_type = check_result.get('result')
                            logger.info(
                                f"sendMessageWithPagination函数验证结果: {function_type}", "api_console_execute")

                            if function_type != 'function':
                                logger.warning(
                                    f"sendMessageWithPagination函数不存在，准备重新注入测试脚本", "api_console_execute")

                                # 尝试重新注入测试脚本
                                logger.info("尝试重新注入console_test.js脚本",
                                            "api_console_execute")
                                inject_result = client_api.inject_javascript(
                                    instance_id,
                                    'js_modules/console_test.js'
                                )

                                if inject_result.get('success'):
                                    logger.info(
                                        "测试脚本重新注入成功", "api_console_execute")

                                    # 再次检查函数
                                    recheck_result = client_api.execute_command(
                                        instance_id,
                                        'executeConsoleCommand',
                                        ["typeof sendMessageWithPagination"]
                                    )

                                    if recheck_result.get('success'):
                                        new_type = recheck_result.get('result')
                                        logger.info(
                                            f"重新验证函数类型: {new_type}", "api_console_execute")
                                else:
                                    logger.error(
                                        f"重新注入测试脚本失败: {inject_result.get('message')}", "api_console_execute")
                        else:
                            logger.warning(
                                f"函数验证失败: {check_result.get('message')}", "api_console_execute")

                    except Exception as check_error:
                        logger.error(
                            f"验证函数存在性时发生错误: {str(check_error)}", "api_console_execute", check_error)

            # 执行命令
            start_time = time.time()
            result = console_manager.execute_command(command)
            execution_time = time.time() - start_time

            # 记录执行结果
            if result.get('success'):
                logger.info(
                    f"控制台命令执行成功，耗时: {execution_time:.3f}秒", "api_console_execute")

                # 检查结果是否包含JavaScript错误
                command_result = result.get('result')
                if isinstance(command_result, dict) and command_result.get('success') is False:
                    error_msg = command_result.get(
                        'message') or command_result.get('error', '未知错误')

                    # 检查是否是函数未定义错误
                    if 'is not defined' in error_msg and 'sendMessageWithPagination' in error_msg:
                        logger.warning(
                            f"检测到sendMessageWithPagination函数未定义错误", "api_console_execute")

                        # 尝试修复函数问题
                        fix_result = client_api.inject_javascript(
                            console_manager.instance_id,
                            'js_modules/console_test.js'
                        )

                        if fix_result.get('success'):
                            logger.info("尝试修复: 重新注入测试脚本成功",
                                        "api_console_execute")

                            # 返回有用的错误信息
                            return jsonify({
                                'success': False,
                                'message': f'JavaScript错误: {error_msg}',
                                'execution_time': execution_time,
                                'command': command,
                                'error_details': command_result,
                                'fix_attempt': '已尝试重新注入脚本，请再次尝试执行命令'
                            })

                    logger.warning(
                        f"命令执行失败: JavaScript错误: {error_msg}", "api_console_execute")
                    logger.operation("控制台命令执行失败", "api_console_execute", {
                        'command': command,
                        'error': f"JavaScript错误: {error_msg}",
                        'execution_time': execution_time
                    })

                    # 返回错误信息
                    return jsonify({
                        'success': False,
                        'message': f'JavaScript错误: {error_msg}',
                        'execution_time': execution_time,
                        'command': command,
                        'error_details': command_result
                    })

                # 记录详细的执行结果
                result_type = type(result.get('result')).__name__
                logger.debug(f"命令执行结果类型: {result_type}", "api_console_execute")
                logger.debug(
                    f"命令执行详细结果: {result.get('result')}", "api_console_execute")

            # 记录操作日志
                logger.operation("控制台命令执行成功", "api_console_execute", {
                    'command': command,
                    'execution_time': execution_time,
                    'result_type': result_type
                })

                # 返回成功结果
                return jsonify({
                    'success': True,
                    'message': '命令执行成功',
                    'execution_time': execution_time,
                    'result': result.get('result'),
                    'command': command
                })
            else:
                error_message = result.get('message', '执行失败')
                logger.warning(
                    f"命令执行失败: {error_message}", "api_console_execute")

                # 记录操作日志
                logger.operation("控制台命令执行失败", "api_console_execute", {
                    'command': command,
                    'error': error_message,
                    'execution_time': execution_time
                })

                # 返回失败结果
                return jsonify({
                    'success': False,
                    'message': error_message,
                    'execution_time': execution_time,
                    'command': command
                })

        except Exception as e:
            logger.error(f"执行控制台命令时发生异常: {str(e)}", "api_console_execute", e)

            # 记录详细的异常信息
            logger.debug(f"异常类型: {type(e).__name__}", "api_console_execute")
            logger.debug(f"异常详情: {str(e)}", "api_console_execute")

            # 记录操作日志
            logger.operation("控制台命令执行异常", "api_console_execute", {
                'command': command,
                'exception': str(e),
                'exception_type': type(e).__name__
            })

            return jsonify({
                'success': False,
                'message': f'执行命令时发生异常: {str(e)}',
                'command': command
            }), 500

    @app.route('/api/console/clear', methods=['POST'])
    def api_console_clear():
        """清空控制台API"""
        logger.debug("清空控制台", "api_console_clear")

        try:
            # 获取控制台管理器
            global console_manager

            if not console_manager:
                logger.error("控制台管理器未初始化", "api_console_clear")
                return jsonify({
                    'success': False,
                    'message': '控制台管理器未初始化'
                }), 500

            # 清空控制台
            result = console_manager.clear_console()

            # 记录操作日志
            if result.get('success'):
                logger.operation("控制台清空成功", "api_console_clear")
            else:
                error_message = result.get('message', '清空控制台失败')
                logger.operation("控制台清空失败", "api_console_clear", {
                    'error': error_message
                })

            return jsonify(result)

        except Exception as e:
            logger.error("处理清空控制台请求时发生异常", "api_console_clear", e)
            logger.debug(f"异常详情: {str(e)}", "api_console_clear")

            # 记录操作日志
            logger.operation("控制台清空异常", "api_console_clear", {
                'exception': str(e)
            })

            return jsonify({
                'success': False,
                'message': f'处理请求时发生异常: {str(e)}'
            }), 500

    @app.route('/api/console/history')
    def api_console_history():
        """获取命令历史API"""
        logger.debug("获取命令历史", "api_console_history")

        try:
            # 获取控制台管理器
            global console_manager

            if not console_manager:
                logger.error("控制台管理器未初始化", "api_console_history")
                return jsonify({
                    'success': False,
                    'message': '控制台管理器未初始化'
                }), 500

            # 获取命令历史
            history = console_manager.get_command_history()

            return jsonify({
                'success': True,
                'history': history
            })

        except Exception as e:
            logger.error("处理获取命令历史请求时发生异常", "api_console_history", e)
            logger.debug(f"异常详情: {str(e)}", "api_console_history")

            # 记录操作日志
            logger.operation("获取命令历史异常", "api_console_history", {
                'exception': str(e)
            })

            return jsonify({
                'success': False,
                'message': f'处理请求时发生异常: {str(e)}'
            }), 500

    @app.route('/api/js-modules')
    def api_js_modules():
        """获取JavaScript模块列表API"""
        logger.debug("获取JavaScript模块列表", "api_js_modules")

        # 验证会话令牌
        if not verify_session_token():
            logger.warning("未验证的用户尝试获取JS模块列表", "api_js_modules")
            return jsonify({
                'success': False,
                'message': '未授权的操作，请重新登录'
            }), 401

        # 确保使用会话中保存的令牌进行请求
        auth_token = session.get('auth_token')
        if auth_token:
            logger.debug(
                f"使用会话令牌获取JS模块列表: {auth_token[:8]}..., 长度={len(auth_token)}", "api_js_modules")
            client_api.session.headers['X-Auth-Token'] = auth_token
        else:
            logger.warning("会话中缺少认证令牌", "api_js_modules")
            return jsonify({
                'success': False,
                'message': '会话令牌缺失，请重新登录'
            }), 401

        try:
            # 调用API获取JavaScript模块列表
            result = client_api.get_js_modules()

            # 清除请求头中的令牌
            if 'X-Auth-Token' in client_api.session.headers:
                del client_api.session.headers['X-Auth-Token']

            # 记录结果
            if result.get('success'):
                modules_count = len(result.get('modules', []))
                logger.info(
                    f"获取到 {modules_count} 个JavaScript模块", "api_js_modules")
                logger.operation("获取JS模块列表成功", "api_js_modules", {
                                 'count': modules_count})
                return jsonify(result)
            else:
                error_message = result.get('message', '获取JavaScript模块列表失败')
                logger.warning(
                    f"获取JavaScript模块列表失败: {error_message}", "api_js_modules")
                logger.operation("获取JS模块列表失败", "api_js_modules", {
                                 'error': error_message})
                return jsonify(result), 400

        except Exception as e:
            logger.error("获取JavaScript模块列表时发生异常", "api_js_modules", e)
            logger.debug(f"异常详情: {str(e)}", "api_js_modules")

            # 清除请求头中的令牌
            if 'X-Auth-Token' in client_api.session.headers:
                del client_api.session.headers['X-Auth-Token']

            # 记录操作日志
            logger.operation("获取JS模块列表异常", "api_js_modules",
                             {'exception': str(e)})

            return jsonify({
                'success': False,
                'message': f'获取JavaScript模块列表时发生异常: {str(e)}'
            }), 500

    @app.route('/api/console/disconnect', methods=['POST'])
    def api_console_disconnect():
        """断开控制台连接"""
        logger.debug("处理控制台断开连接请求", "api_console_disconnect")
        
        # 验证会话
        if not verify_session_token():
            logger.warning("未授权的控制台断开连接请求", "api_console_disconnect")
            return jsonify({
                'success': False,
                'message': '未授权的请求',
                'error_code': 'UNAUTHORIZED'
            }), 401
        
        try:
            # 获取当前用户信息
            username = session.get('username', 'unknown')
            user_id = session.get('user_info', {}).get('id', 'unknown')
            
            # 检查控制台管理器是否存在
            global console_manager
            if not console_manager:
                logger.warning("控制台管理器未初始化，无需断开连接", "api_console_disconnect")
                return jsonify({
                    'success': True,
                    'message': '控制台管理器未初始化，无需断开连接',
                    'status': 'NOT_INITIALIZED'
                })
            
            # 获取当前连接的实例ID
            current_instance_id = console_manager.instance_id
            logger.debug(f"当前连接的实例ID: {current_instance_id}", "api_console_disconnect")
            
            # 检查是否已连接
            if not console_manager.connected or not current_instance_id:
                logger.info("控制台未连接，无需断开", "api_console_disconnect")
                return jsonify({
                    'success': True,
                    'message': '控制台未连接，无需断开',
                    'status': 'NOT_CONNECTED'
                })
            
            # 记录断开连接前的状态
            logger.info(f"断开前控制台状态: connected={console_manager.connected}, instance_id={current_instance_id}", "api_console_disconnect")
            
            # 断开控制台连接
            logger.info("开始断开控制台连接", "api_console_disconnect")
            result = console_manager.disconnect()
            
            # 记录断开连接后的状态
            logger.info(f"断开后控制台状态: connected={console_manager.connected}, instance_id={console_manager.instance_id}", "api_console_disconnect")
            
            if result.get('success'):
                logger.info("控制台断开连接成功", "api_console_disconnect")
                logger.operation("控制台断开连接成功", "api_console_disconnect", {
                    'username': username,
                    'user_id': user_id,
                    'instance_id': current_instance_id
                })
                
                # 返回成功结果
                return jsonify({
                    'success': True,
                    'message': '控制台已断开连接',
                    'instance_id': current_instance_id
                })
            else:
                # 记录错误
                error_message = result.get('message', '断开连接失败: 未知错误')
                error_code = result.get('error_code', 'DISCONNECT_ERROR')
                logger.warning(f"控制台断开连接失败: {error_message}", "api_console_disconnect")
                logger.warning(f"错误代码: {error_code}", "api_console_disconnect")
                logger.warning(f"错误详情: {result}", "api_console_disconnect")
                
                logger.operation("控制台断开连接失败", "api_console_disconnect", {
                    'username': username,
                    'user_id': user_id,
                    'instance_id': current_instance_id,
                    'error': error_message,
                    'error_code': error_code
                })
                
                # 尝试强制重置控制台状态
                try:
                    logger.info("尝试强制重置控制台状态", "api_console_disconnect")
                    console_manager.connected = False
                    console_manager.instance_id = None
                    if console_manager.devtools_manager:
                        console_manager.devtools_manager.connected = False
                        console_manager.devtools_manager.instance_id = None
                    logger.info("控制台状态已强制重置", "api_console_disconnect")
                except Exception as reset_e:
                    logger.warning(f"强制重置控制台状态失败: {reset_e}", "api_console_disconnect")
                
                # 返回错误结果
                return jsonify({
                    'success': False,
                    'message': error_message,
                    'error_code': error_code,
                    'instance_id': current_instance_id,
                    'forced_reset': True
                })
                
        except Exception as e:
            # 记录异常
            logger.error("断开控制台连接时发生异常", "api_console_disconnect", e)
            logger.error(f"异常详情: {str(e)}", "api_console_disconnect")
            logger.error(f"异常堆栈: {traceback.format_exc()}", "api_console_disconnect")
            
            # 获取当前用户信息
            username = session.get('username', 'unknown')
            user_id = session.get('user_info', {}).get('id', 'unknown')
            
            # 尝试获取实例ID（如果可能）
            instance_id = "unknown"
            if console_manager and hasattr(console_manager, 'instance_id'):
                instance_id = console_manager.instance_id or "unknown"
            
            # 记录操作日志
            logger.operation("控制台断开连接异常", "api_console_disconnect", {
                'username': username,
                'user_id': user_id,
                'instance_id': instance_id,
                'exception': str(e),
                'exception_type': type(e).__name__
            })
            
            # 尝试强制重置控制台状态
            try:
                if console_manager:
                    logger.info("异常处理中尝试强制重置控制台状态", "api_console_disconnect")
                    console_manager.connected = False
                    console_manager.instance_id = None
                    if console_manager.devtools_manager:
                        console_manager.devtools_manager.connected = False
                        console_manager.devtools_manager.instance_id = None
                    logger.info("异常处理中控制台状态已强制重置", "api_console_disconnect")
            except Exception as reset_e:
                logger.warning(f"异常处理中强制重置控制台状态失败: {reset_e}", "api_console_disconnect")
            
            # 返回错误结果
            return jsonify({
                'success': False,
                'message': f'断开连接失败: {str(e)}',
                'error_code': 'DISCONNECT_EXCEPTION',
                'exception': str(e),
                'exception_type': type(e).__name__,
                'forced_reset': True
            })

    logger.debug("路由注册完成", "register_routes")


def register_socketio_events(socketio: SocketIO) -> None:
    """
    注册SocketIO事件

    Args:
        socketio: SocketIO实例
    """
    logger.debug("开始注册SocketIO事件", "register_socketio_events")

    @socketio.on('connect')
    def handle_connect():
        """连接事件处理"""
        logger.debug("SocketIO客户端连接", "handle_connect")

        # 声明全局变量
        global client_api, console_manager

        # 检查会话
        if session:
            session_keys = list(session.keys())
            session_id = session.sid if hasattr(session, 'sid') else 'unknown'
            logger.debug(
                f"WebSocket连接的会话ID: {session_id}, 会话键: {session_keys}", "handle_connect")

            # 记录令牌信息
            auth_token = session.get('auth_token')
            if auth_token:
                logger.debug(f"会话中存在令牌，长度={len(auth_token)}", "handle_connect")

                # 确保API客户端也有令牌
                if client_api and not client_api.current_token:
                    logger.debug("从会话中恢复API客户端令牌", "handle_connect")
                    client_api.current_token = auth_token
                    client_api.is_authenticated = True
                    # 从会话中恢复用户信息
                    client_api.current_user = session.get('user_info', {})
            else:
                logger.warning("会话中缺少令牌", "handle_connect")

                # 尝试从API客户端恢复令牌
                if client_api and client_api.current_token:
                    logger.debug("从API客户端恢复会话令牌", "handle_connect")
                    session['auth_token'] = client_api.current_token
                    session.modified = True

            # 确保会话是永久的
            if not session.permanent and len(session_keys) > 0:
                logger.warning("WebSocket连接的会话未设置为永久，正在修复", "handle_connect")
                session.permanent = True
                session.modified = True
                logger.debug("已将WebSocket连接的会话设置为永久", "handle_connect")

            # 检查令牌过期时间
            token_expiry = session.get('token_expiry', 0)
            current_time = time.time()
            if token_expiry:
                remaining_time = token_expiry - current_time
                if remaining_time > 0:
                    remaining_hours = remaining_time / 3600
                    logger.debug(
                        f"令牌剩余有效期: {remaining_hours:.2f}小时", "handle_connect")
                else:
                    logger.warning(
                        f"令牌已过期 {-remaining_time:.1f}秒", "handle_connect")
        else:
            logger.debug("无会话信息", "handle_connect")

        # 验证会话令牌
        token_valid = verify_session_token()
        logger.debug(f"WebSocket连接会话令牌验证结果: {token_valid}", "handle_connect")

        if not token_valid:
            logger.warning("未验证的用户尝试WebSocket连接", "handle_connect")
            # 发送错误消息
            emit('system', {
                'type': 'error',
                'message': '未授权的连接，请重新登录'
            })
            # 断开连接
            disconnect()
            return False

        # 记录当前用户名和令牌信息
        username = session.get('username', '未知用户')
        auth_token = session.get('auth_token')

        if auth_token:
            logger.info(
                f"WebSocket连接已验证: 用户={username}, 令牌长度={len(auth_token)}", "handle_connect")
        else:
            logger.warning(
                f"WebSocket连接已验证但缺少令牌: 用户={username}", "handle_connect")

        # 记录操作日志
        logger.operation("WebSocket连接成功", "handle_connect", {
            'username': username,
            'has_token': auth_token is not None,
            'token_length': len(auth_token) if auth_token else 0,
            'session_id': session.sid if hasattr(session, 'sid') else 'unknown'
        })

        # 发送欢迎消息
        emit('system', {
            'type': 'info',
            'message': f'欢迎回来，{username}'
        })

        # 获取控制台管理器
        global console_manager

        # 如果控制台已连接，发送状态更新
        if console_manager and console_manager.connected:
            logger.debug("发送控制台状态更新", "handle_connect")
            emit('console_status', {
                'connected': True,
                'instance_id': console_manager.instance_id
            })

            # 发送控制台缓冲区内容
            if console_manager.console_buffer:
                logger.debug(
                    f"发送控制台缓冲区，{len(console_manager.console_buffer)}条消息", "handle_connect")
                emit('console_output', {
                    'messages': console_manager.console_buffer
                })
        else:
            logger.debug("控制台未连接，发送断开状态", "handle_connect")
            emit('console_status', {
                'connected': False,
                'instance_id': None
            })

    @socketio.on('disconnect')
    def handle_disconnect():
        """断开连接事件处理"""
        logger.debug("SocketIO客户端断开连接", "handle_disconnect")

        # 记录会话信息
        try:
            session_id = session.sid if hasattr(session, 'sid') else 'unknown'
            username = session.get('username', '未知用户')
            auth_token = session.get('auth_token')

            logger.debug(
                f"断开连接的会话信息: ID={session_id}, 用户={username}, 令牌存在={auth_token is not None}", "handle_disconnect")

            # 确保会话持久化
            if session and len(session.keys()) > 0:
                # 更新最后活动时间
                session['last_activity'] = time.time()
                # 确保会话是永久的
                session.permanent = True
                # 标记会话已修改
                session.modified = True
                logger.debug("已更新会话最后活动时间并确保持久化", "handle_disconnect")

            # 记录操作日志
            logger.operation("WebSocket连接断开", "handle_disconnect", {
                'username': username,
                'session_id': session_id,
                'has_token': auth_token is not None
            })

        except Exception as e:
            logger.debug(f"获取断开连接的会话信息失败: {str(e)}", "handle_disconnect")

    @socketio.on('console_command')
    def handle_console_command(data):
        """
        控制台命令事件处理

        Args:
            data: 命令数据
        """
        logger.debug(f"收到控制台命令: {data}", "handle_console_command")
        logger.info(f"收到WebSocket控制台命令请求，时间戳: {data.get('timestamp', 'unknown')}", "handle_console_command")

        # 声明全局变量
        global client_api, console_manager

        # 验证会话令牌
        token_valid = verify_session_token()
        logger.debug(f"会话令牌验证结果: {token_valid}", "handle_console_command")

        if not token_valid:
            logger.warning("未验证的用户尝试执行控制台命令", "handle_console_command")
            emit('system', {
                'type': 'error',
                'message': '未授权的操作，请重新登录'
            })
            return

        try:
            # 获取命令
            command = data.get('command')

            if not command:
                logger.warning("命令为空", "handle_console_command")
                emit('system', {
                    'type': 'warning',
                    'message': '命令不能为空'
                })
                return

            # 检查控制台管理器
            if not console_manager:
                logger.error("控制台管理器未初始化", "handle_console_command")
                logger.debug("控制台管理器状态: None", "handle_console_command")
                emit('system', {
                    'type': 'error',
                    'message': '控制台管理器未初始化'
                })
                return

            # 检查连接状态
            if not console_manager.connected:
                logger.warning("控制台未连接，无法执行命令", "handle_console_command")
                logger.debug(f"控制台连接状态: {console_manager.connected}", "handle_console_command")
                logger.debug(f"控制台实例ID: {console_manager.instance_id}", "handle_console_command")
                emit('system', {
                    'type': 'warning',
                    'message': '控制台未连接，请先连接到实例'
                })
                return
                
            logger.debug(f"控制台连接状态检查通过，已连接到实例: {console_manager.instance_id}", "handle_console_command")

            # 确保使用会话中保存的令牌进行请求
            auth_token = session.get('auth_token')
            original_token = None

            if auth_token:
                logger.debug(
                    f"使用会话令牌执行WebSocket命令: {auth_token[:8]}..., 长度={len(auth_token)}", "handle_console_command")

                # 记录令牌详情
                token_expiry = session.get('token_expiry', 0)
                current_time = time.time()
                if token_expiry:
                    remaining_time = token_expiry - current_time
                    remaining_hours = remaining_time / 3600
                    logger.debug(
                        f"令牌过期信息: 剩余时间={remaining_hours:.2f}小时, 过期时间={time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(token_expiry))}", "handle_console_command")

                                    # 确保API客户端也有令牌
                    if client_api:
                        # 保存原始令牌
                        original_token = client_api.current_token

                        # 临时设置令牌用于请求
                        client_api.current_token = auth_token
                        client_api.session.headers['X-Auth-Token'] = auth_token
                        logger.debug("已临时设置API客户端令牌", "handle_console_command")
            else:
                logger.warning("会话中缺少认证令牌", "handle_console_command")

                # 尝试从API客户端获取令牌
                if client_api and client_api.current_token:
                    logger.debug(
                        f"从API客户端获取令牌: {client_api.current_token[:8]}...", "handle_console_command")
                    auth_token = client_api.current_token

                    # 保存到会话
                    session['auth_token'] = auth_token
                    session.modified = True
                    logger.debug("已将API客户端令牌保存到会话", "handle_console_command")

                    # 设置请求头
                    client_api.session.headers['X-Auth-Token'] = auth_token
                else:
                    logger.error("无法获取认证令牌，无法执行命令", "handle_console_command")
                    emit('system', {
                        'type': 'error',
                        'message': '会话令牌缺失，请重新登录'
                    })
                    return

            # 检查是否是特殊函数调用
            if 'sendMessageWithPagination' in command:
                logger.debug(
                    f"检测到sendMessageWithPagination函数调用: {command}", "handle_console_command")

                # 检查令牌过期信息
                if client_api and client_api.current_token:
                    # 假设令牌有效期为24小时，计算剩余时间
                    token_expiry = session.get(
                        'token_expiry', time.time() + 86400)
                    remaining_time = token_expiry - time.time()
                    remaining_hours = remaining_time / 3600
                    expiry_time = time.strftime(
                        '%Y-%m-%d %H:%M:%S', time.localtime(token_expiry))

                    logger.debug(
                        f"令牌过期信息: 剩余时间={remaining_hours:.2f}小时, 过期时间={expiry_time}", "handle_console_command")

            # 执行命令
            try:
                logger.info(f"开始执行控制台命令: {command}", "handle_console_command")
                start_time = time.time()
                result = console_manager.execute_command(command)
                execution_time = time.time() - start_time
                logger.debug(f"命令执行完成，耗时: {execution_time:.3f}秒", "handle_console_command")
                logger.debug(f"命令执行结果: {result}", "handle_console_command")

                # 记录结果
                if result.get('success'):
                    logger.debug(
                        f"命令执行成功，耗时: {execution_time:.3f}秒", "handle_console_command")

                    # 检查JavaScript执行结果
                    js_result = result.get('result', {})
                    if isinstance(js_result, dict) and js_result.get('success') is False:
                        error_msg = js_result.get(
                            'error', js_result.get('message', '未知JavaScript错误'))
                        logger.warning(
                            f"JavaScript执行错误: {error_msg}", "handle_console_command")

                        # 记录详细的错误信息
                        logger.debug(
                            f"JavaScript错误详情: {js_result}", "handle_console_command")

                        # 发送JavaScript错误消息
                        emit('system', {
                            'type': 'error',
                            'message': f'JavaScript错误: {error_msg}'
                        })
                        logger.debug("已发送JavaScript错误消息到客户端", "handle_console_command")

                    # 记录操作日志
                    result_type = type(result.get('result')).__name__
                    logger.debug(
                        f"命令执行结果类型: {result_type}", "handle_console_command")

                    # 如果是sendMessageWithPagination函数，记录更详细的结果信息
                    if 'sendMessageWithPagination' in command:
                        logger.debug(
                            "记录sendMessageWithPagination执行结果详情", "handle_console_command")
                        if isinstance(js_result, dict):
                            # 记录结果信息
                            success = js_result.get('success', False)
                            message = js_result.get('message', '')
                            pages = js_result.get('pages', 0)

                            logger.info(
                                f"sendMessageWithPagination执行结果: 成功={success}, 消息={message}, 页数={pages}", "handle_console_command")

                            # 记录详细的数据结构
                            if 'data' in js_result:
                                data = js_result.get('data', {})
                                pagination = data.get('pagination', {})
                                execution = data.get('execution', {})

                                logger.debug(
                                    f"翻页详情: 启用={pagination.get('enabled', False)}, 页数={pagination.get('pages', 0)}", "handle_console_command")
                                logger.debug(
                                    f"执行详情: 耗时={execution.get('duration', 0)}ms, 模式={execution.get('mode', '未知')}", "handle_console_command")

                    logger.operation("WebSocket控制台命令执行成功", "handle_console_command", {
                        'command': command,
                        'execution_time': execution_time,
                        'result_type': result_type
                    })
                else:
                    error_message = result.get('message', '执行失败')
                    logger.warning(
                        f"命令执行失败: {error_message}", "handle_console_command")
                    logger.debug(f"失败详情: {result}", "handle_console_command")

                    # 发送错误消息
                    emit('system', {
                        'type': 'error',
                        'message': f'执行失败: {error_message}'
                    })
                    logger.debug("已发送错误消息到客户端", "handle_console_command")

                    # 记录操作日志
                    logger.operation("WebSocket控制台命令执行失败", "handle_console_command", {
                        'command': command,
                        'error': error_message
                    })
            finally:
                # 清除请求头中的令牌
                if client_api and 'X-Auth-Token' in client_api.session.headers:
                    del client_api.session.headers['X-Auth-Token']
                    logger.debug("已清除API客户端请求头中的令牌", "handle_console_command")

                # 恢复原始令牌（如果有）
                if client_api and original_token:
                    client_api.current_token = original_token
                    logger.debug("已恢复API客户端原始令牌", "handle_console_command")

        except Exception as e:
            logger.error("处理控制台命令时发生异常", "handle_console_command", e)
            logger.error(f"异常详情: {str(e)}", "handle_console_command")
            logger.error(f"异常堆栈: {traceback.format_exc()}", "handle_console_command")

            # 清除请求头中的令牌
            if client_api and 'X-Auth-Token' in client_api.session.headers:
                del client_api.session.headers['X-Auth-Token']

            # 记录操作日志
            logger.operation("WebSocket控制台命令执行异常", "handle_console_command", {
                'command': data.get('command', '未知'),
                'exception': str(e)
            })

            # 发送错误消息
            emit('system', {
                'type': 'error',
                'message': f'执行命令时发生异常: {str(e)}'
            })
            logger.debug("已发送异常错误消息到客户端", "handle_console_command")

    logger.debug("SocketIO事件注册完成", "register_socketio_events")


def console_output_handler(messages):
    """
    控制台输出处理函数

    Args:
        messages: 控制台消息列表
    """
    logger.debug(f"处理控制台输出: {len(messages)}条消息", "console_output_handler")

    try:
        # 记录消息详情
        if messages:
            # 记录消息类型统计
            type_counts = {}
            level_counts = {}
            for msg in messages:
                msg_type = msg.get('type', 'unknown')
                msg_level = msg.get('level', 'unknown')
                type_counts[msg_type] = type_counts.get(msg_type, 0) + 1
                level_counts[msg_level] = level_counts.get(msg_level, 0) + 1

            logger.debug(f"消息类型统计: {type_counts}", "console_output_handler")
            logger.debug(f"消息级别统计: {level_counts}", "console_output_handler")

            # 记录几条消息内容示例
            for i, msg in enumerate(messages[:5]):
                content = msg.get('content', '')[:100]
                msg_type = msg.get('type', 'unknown')
                msg_level = msg.get('level', 'unknown')
                msg_time = datetime.fromtimestamp(
                    msg.get('timestamp', 0)/1000).strftime('%H:%M:%S')
                logger.debug(
                    f"消息 {i+1}/{min(5, len(messages))}: [{msg_time}][{msg_type}][{msg_level}] {content}", "console_output_handler")

        # 确保所有消息都有必要的字段
        validated_messages = []
        for msg in messages:
            # 验证消息格式
            if not isinstance(msg, dict):
                logger.warning(
                    f"跳过非字典类型的消息: {type(msg).__name__}", "console_output_handler")
                continue

            # 确保消息包含必要的字段
            validated_msg = msg.copy()  # 创建副本以避免修改原始数据

            if 'type' not in validated_msg:
                validated_msg['type'] = 'console'
                logger.debug("为消息添加默认类型: console", "console_output_handler")

            if 'content' not in validated_msg:
                validated_msg['content'] = str(msg)
                logger.debug("为消息添加默认内容", "console_output_handler")

            if 'timestamp' not in validated_msg:
                validated_msg['timestamp'] = int(time.time() * 1000)
                logger.debug("为消息添加默认时间戳", "console_output_handler")

            if 'level' not in validated_msg:
                validated_msg['level'] = 'log'
                logger.debug("为消息添加默认级别: log", "console_output_handler")

            validated_messages.append(validated_msg)

        # 广播消息
        logger.debug(f"开始广播 {len(validated_messages)} 条消息到前端",
                     "console_output_handler")
        socketio.emit('console_output', {
            'messages': validated_messages,
            'timestamp': int(time.time() * 1000)
        })
        logger.debug(f"消息广播完成", "console_output_handler")

        # 记录操作日志
        logger.operation("控制台消息广播", "console_output_handler", {
            'count': len(validated_messages),
            'types': type_counts if 'type_counts' in locals() else {},
            'levels': level_counts if 'level_counts' in locals() else {}
        })
    except Exception as e:
        logger.error("广播控制台输出时发生异常", "console_output_handler", e)
        logger.debug(f"异常详情: {str(e)}", "console_output_handler")
        logger.debug(
            f"消息数量: {len(messages) if messages else 0}", "console_output_handler")

        # 尝试记录第一条消息的内容（如果存在）
        if messages and len(messages) > 0:
            try:
                first_msg = messages[0]
                logger.debug(f"第一条消息: {first_msg}", "console_output_handler")
            except Exception as msg_e:
                logger.error("尝试记录第一条消息时发生异常", "console_output_handler", msg_e)


def console_error_handler(error_message):
    """
    控制台错误处理函数

    Args:
        error_message: 错误消息
    """
    logger.debug(f"处理控制台错误: {error_message}", "console_error_handler")

    try:
        # 广播错误消息
        socketio.emit('system', {
            'type': 'error',
            'message': error_message
        })
    except Exception as e:
        logger.error("广播控制台错误时发生异常", "console_error_handler", e)
        logger.debug(f"异常详情: {str(e)}", "console_error_handler")


def console_status_change_handler(connected, instance_id):
    """
    控制台状态变更处理函数

    Args:
        connected: 是否已连接
        instance_id: 实例ID
    """
    logger.debug(
        f"处理控制台状态变更: connected={connected}, instance_id={instance_id}", "console_status_change_handler")

    try:
        # 广播状态变更
        socketio.emit('console_status', {
            'connected': connected,
            'instance_id': instance_id
        })

        # 广播系统消息
        if connected:
            socketio.emit('system', {
                'type': 'success',
                'message': f'已连接到实例: {instance_id}'
            })
        else:
            socketio.emit('system', {
                'type': 'info',
                'message': '已断开控制台连接'
            })
    except Exception as e:
        logger.error("广播控制台状态变更时发生异常", "console_status_change_handler", e)
        logger.debug(f"异常详情: {str(e)}", "console_status_change_handler")


def check_port_available(port: int, host: str = '127.0.0.1') -> bool:
    """
    检查端口是否可用

    Args:
        port: 要检查的端口号
        host: 主机地址

    Returns:
        bool: 端口是否可用
    """
    import socket

    logger.debug(f"检查端口 {port} 是否可用", "check_port_available")

    try:
        # 尝试绑定端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            logger.debug(f"端口 {port} 可用", "check_port_available")
            return True
    except OSError as e:
        logger.warning(f"端口 {port} 不可用: {str(e)}", "check_port_available")
        return False


def run_client_web_app(port: int = 5001, server_url: str = 'http://127.0.0.1:5000', host: str = '127.0.0.1') -> None:
    """
    运行客户端Web应用

    Args:
        port: 端口号
        server_url: 服务器地址
        host: 主机地址
    """
    logger.info(
        f"启动客户端Web应用: port={port}, server_url={server_url}, host={host}", "run_client_web_app")

    # 检查端口是否可用
    if not check_port_available(port, host):
        logger.error(f"端口 {port} 已被占用，无法启动应用", "run_client_web_app")
        print(f"\n[错误] 端口 {port} 已被占用，请尝试使用其他端口或关闭占用该端口的应用")
        print(f"[建议] 可以使用 --port 参数指定其他端口，例如: python start_client.py --port 5002\n")
        return

    # 确保会话目录存在
    session_dir = 'flask_session'
    if not os.path.exists(session_dir):
        os.makedirs(session_dir, exist_ok=True)
        logger.info(f"创建会话存储目录: {session_dir}", "run_client_web_app")

        # 设置会话目录权限
        try:
            os.chmod(session_dir, 0o700)  # 只允许所有者访问
            logger.debug(f"设置会话目录权限: 0700", "run_client_web_app")
        except Exception as e:
            logger.warning(f"无法设置会话目录权限: {str(e)}", "run_client_web_app")
    else:
        # 检查会话文件数量和权限
        try:
            session_files = [f for f in os.listdir(
                session_dir) if os.path.isfile(os.path.join(session_dir, f))]
            logger.info(
                f"会话存储目录已存在，包含 {len(session_files)} 个会话文件", "run_client_web_app")

            # 检查会话文件权限
            for session_file in session_files:
                file_path = os.path.join(session_dir, session_file)
                try:
                    # 确保会话文件有正确的权限
                    os.chmod(file_path, 0o600)
                except Exception as perm_e:
                    logger.warning(
                        f"无法设置会话文件权限: {file_path}, 错误: {str(perm_e)}", "run_client_web_app")

            logger.debug("会话文件权限检查完成", "run_client_web_app")

            # 检查会话目录权限
            try:
                os.chmod(session_dir, 0o700)  # 只允许所有者访问
                logger.debug(f"设置会话目录权限: 0700", "run_client_web_app")
            except Exception as e:
                logger.warning(f"无法设置会话目录权限: {str(e)}", "run_client_web_app")
        except Exception as e:
            logger.warning(f"检查会话文件异常: {str(e)}", "run_client_web_app")

    # 创建应用
    app = create_app(server_url=server_url)

    # 输出会话配置信息
    logger.info(f"会话配置: 类型={app.config.get('SESSION_TYPE')}, 持久化={app.config.get('SESSION_PERMANENT')}, "
                f"有效期={app.config['PERMANENT_SESSION_LIFETIME']}秒, Cookie名称={app.config.get('SESSION_COOKIE_NAME')}", "run_client_web_app")

    # 运行应用
    try:
        logger.info(
            f"客户端Web应用开始运行: http://{host}:{port}", "run_client_web_app")
        logger.debug(
            f"SocketIO配置: async_mode={socketio.async_mode}, manage_session={socketio.manage_session}", "run_client_web_app")
        socketio.run(app, host=host, port=port, debug=False,
                     allow_unsafe_werkzeug=True)
    except OSError as e:
        if "Address already in use" in str(e):
            logger.error(f"端口 {port} 已被占用，请尝试使用其他端口或关闭占用该端口的应用",
                         "run_client_web_app", e)
            logger.debug(f"端口占用错误: {str(e)}", "run_client_web_app")
            print(f"\n[错误] 端口 {port} 已被占用，请尝试使用其他端口或关闭占用该端口的应用")
            print(
                f"[建议] 可以使用 --port 参数指定其他端口，例如: python start_client.py --port 5002\n")
        else:
            logger.error(f"客户端Web应用运行异常: {str(e)}", "run_client_web_app", e)
            logger.debug(
                f"操作系统错误: {type(e).__name__}, 详情: {str(e)}", "run_client_web_app")
            print(f"\n[错误] 启动Web应用时发生系统错误: {str(e)}\n")
        raise
    except Exception as e:
        logger.error(f"客户端Web应用运行异常: {str(e)}", "run_client_web_app", e)
        logger.debug(
            f"异常类型: {type(e).__name__}, 异常详情: {str(e)}", "run_client_web_app")
        print(f"\n[错误] 客户端Web应用启动失败: {str(e)}")
        print("[建议] 请检查日志文件获取详细信息，或尝试重启应用\n")
        raise
