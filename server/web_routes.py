#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web界面路由模块
处理Web页面路由、用户认证跳转、模板渲染等功能
提供完整的Web管理界面支持
"""

import os
import time
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from flask import request, render_template, redirect, url_for, flash, jsonify, Blueprint, session, current_app, send_from_directory
from flask_login import login_required, current_user, logout_user

from .logger import get_server_logger
from .auth import auth_manager, get_current_user_info
from .instance_manager import instance_pool
from .js_manager import get_js_manager
from .config import config_manager

# 获取服务端日志实例
logger = get_server_logger()

# 创建蓝图
bp = Blueprint('web_routes', __name__)

def register_web_routes(app):
    """注册Web界面路由"""
    logger.info("开始注册Web界面路由", "register_web_routes")
    
    # ================================
    # 主页和认证相关页面路由
    # ================================
    
    @app.route('/')
    def index():
        """首页 - 根据认证状态自动跳转"""
        logger.info("处理首页访问请求", "index")
        logger.debug(f"用户认证状态: {current_user.is_authenticated}", "index")
        logger.debug(f"请求来源IP: {request.remote_addr}", "index")
        logger.debug(f"用户代理: {request.headers.get('User-Agent', '未知')}", "index")
        
        try:
            # 检查用户是否已经登录
            if current_user.is_authenticated:
                logger.info(f"用户已登录，跳转到仪表板: {current_user.username}", "index")
                logger.operation("已登录用户访问首页，重定向到仪表板", "index", {
                    'username': current_user.username,
                    'redirect_to': 'dashboard'
                })
                return redirect(url_for('dashboard'))
            else:
                logger.info("用户未登录，跳转到登录页面", "index")
                logger.operation("未登录用户访问首页，重定向到登录页", "index", {
                    'remote_addr': request.remote_addr,
                    'redirect_to': 'login_page'
                })
                return redirect(url_for('login_page'))
                
        except Exception as e:
            logger.error("处理首页请求发生异常", "index", e)
            logger.operation("首页访问异常", "index", {
                'error': str(e),
                'remote_addr': request.remote_addr
            })
            # 发生异常时跳转到登录页面
            return redirect(url_for('login_page'))
    
    @app.route('/login')
    def login_page():
        """登录页面"""
        logger.info("处理登录页面访问请求", "login_page")
        logger.debug(f"用户认证状态: {current_user.is_authenticated}", "login_page")
        logger.debug(f"请求来源IP: {request.remote_addr}", "login_page")
        
        try:
            # 如果用户已经登录，直接跳转到仪表板
            if current_user.is_authenticated:
                logger.info(f"用户已登录，从登录页跳转到仪表板: {current_user.username}", "login_page")
                logger.operation("已登录用户访问登录页，重定向到仪表板", "login_page", {
                    'username': current_user.username,
                    'action': 'auto_redirect'
                })
                return redirect(url_for('dashboard'))
            
            # 显示登录页面
            logger.debug("渲染登录页面模板", "login_page")
            logger.operation("显示登录页面", "login_page", {
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', '未知')
            })
            
            return render_template('login.html')
            
        except Exception as e:
            logger.error("处理登录页面请求发生异常", "login_page", e)
            logger.operation("登录页面访问异常", "login_page", {
                'error': str(e),
                'remote_addr': request.remote_addr
            })
            # 返回简单的登录页面
            return render_fallback_login_page()
    
    @app.route('/logout')
    @login_required
    def logout_page():
        """用户注销"""
        logger.info(f"处理用户注销请求: {current_user.username}", "logout_page")
        logger.debug(f"注销前用户信息: {current_user.username}", "logout_page")
        
        try:
            # 记录注销前的用户信息
            username = current_user.username if current_user.is_authenticated else '未知用户'
            
            # 执行注销操作
            logger.debug("执行Flask-Login注销", "logout_page")
            logout_user()
            
            # 清除会话数据
            logger.debug("清除用户会话数据", "logout_page")
            
            logger.info(f"用户注销成功: {username}", "logout_page")
            logger.operation("用户注销成功", "logout_page", {
                'username': username,
                'logout_time': time.time(),
                'remote_addr': request.remote_addr
            })
            
            # 跳转到登录页面
            return redirect(url_for('login_page'))
            
        except Exception as e:
            logger.error("处理用户注销请求发生异常", "logout_page", e)
            logger.operation("用户注销异常", "logout_page", {
                'error': str(e),
                'username': current_user.username if current_user.is_authenticated else '未知'
            })
            # 即使出现异常也要跳转到登录页
            return redirect(url_for('login_page'))
    
    # ================================
    # 后台管理页面路由
    # ================================
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        """管理仪表板"""
        logger.info(f"处理仪表板访问请求: {current_user.username}", "dashboard")
        logger.debug(f"用户权限: {current_user.account.permissions}", "dashboard")
        
        try:
            # 检查用户权限
            if not auth_manager.check_user_permission('view'):
                logger.warning(f"用户无权限访问仪表板: {current_user.username}", "dashboard")
                logger.operation("仪表板访问被拒绝：权限不足", "dashboard", {
                    'username': current_user.username,
                    'required_permission': 'view',
                    'user_permissions': current_user.account.permissions
                })
                return render_template('error.html', 
                                     error_message='您没有权限访问此页面',
                                     error_code='PERMISSION_DENIED'), 403
            
            # 记录仪表板访问
            logger.debug("渲染仪表板页面模板", "dashboard")
            logger.operation("用户访问仪表板", "dashboard", {
                'username': current_user.username,
                'access_time': time.time(),
                'remote_addr': request.remote_addr
            })
            
            return render_template('dashboard.html', 
                                 current_user=current_user,
                                 page_title='管理控制台')
            
        except Exception as e:
            logger.error("处理仪表板请求发生异常", "dashboard", e)
            logger.operation("仪表板访问异常", "dashboard", {
                'error': str(e),
                'username': current_user.username,
                'remote_addr': request.remote_addr
            })
            return render_template('error.html', 
                                 error_message='系统内部错误',
                                 error_code='INTERNAL_ERROR'), 500
    
    @app.route('/instances')
    @login_required
    def instances_page():
        """实例管理页面"""
        logger.info(f"处理实例管理页面访问: {current_user.username}", "instances_page")
        
        try:
            # 检查用户权限
            if not auth_manager.check_user_permission('manage'):
                logger.warning(f"用户无权限访问实例管理: {current_user.username}", "instances_page")
                return render_template('error.html', 
                                     error_message='您没有权限管理实例',
                                     error_code='PERMISSION_DENIED'), 403
            
            logger.operation("用户访问实例管理页面", "instances_page", {
                'username': current_user.username,
                'access_time': time.time()
            })
            
            return render_template('instances.html', 
                                 current_user=current_user,
                                 page_title='实例管理')
            
        except Exception as e:
            logger.error("处理实例管理请求发生异常", "instances_page", e)
            return render_template('error.html', 
                                 error_message='系统内部错误',
                                 error_code='INTERNAL_ERROR'), 500
    
    @app.route('/system-status')
    @login_required
    def system_status():
        """系统状态页面"""
        logger.info(f"处理系统状态页面访问: {current_user.username}", "system_status")
        
        try:
            # 检查用户权限
            if not auth_manager.check_user_permission('view'):
                logger.warning(f"用户无权限访问系统状态: {current_user.username}", "system_status")
                return render_template('error.html', 
                                     error_message='您没有权限查看系统状态',
                                     error_code='PERMISSION_DENIED'), 403
            
            logger.operation("用户访问系统状态页面", "system_status", {
                'username': current_user.username,
                'access_time': time.time()
            })
            
            return render_template('system_status.html', 
                                 current_user=current_user,
                                 page_title='系统状态')
            
        except Exception as e:
            logger.error("处理系统状态请求发生异常", "system_status", e)
            return render_template('error.html', 
                                 error_message='系统内部错误',
                                 error_code='INTERNAL_ERROR'), 500
    
    # ================================
    # 错误处理路由
    # ================================
    
    @app.errorhandler(404)
    def not_found(error):
        """404错误处理"""
        logger.warning(f"404错误: 页面未找到 - {request.url}", "not_found")
        logger.operation("404错误", "not_found", {
            'url': request.url,
            'remote_addr': request.remote_addr,
            'user': current_user.username if current_user.is_authenticated else '未登录'
        })
        
        return render_template('error.html', 
                             error_message='页面未找到',
                             error_code='404'), 404
    
    @app.errorhandler(403)
    def forbidden(error):
        """403错误处理"""
        logger.warning(f"403错误: 访问被拒绝 - {request.url}", "forbidden")
        logger.operation("403错误", "forbidden", {
            'url': request.url,
            'remote_addr': request.remote_addr,
            'user': current_user.username if current_user.is_authenticated else '未登录'
        })
        
        return render_template('error.html', 
                             error_message='您没有权限访问此页面',
                             error_code='403'), 403
    
    @app.errorhandler(500)
    def internal_error(error):
        """500错误处理"""
        logger.error(f"500错误: 内部服务器错误 - {request.url}", "internal_error", error)
        logger.operation("500错误", "internal_error", {
            'url': request.url,
            'remote_addr': request.remote_addr,
            'user': current_user.username if current_user.is_authenticated else '未登录',
            'error': str(error)
        })
        
        return render_template('error.html', 
                             error_message='系统内部错误',
                             error_code='500'), 500
    
    # DevTools相关路由
    @app.route('/api/instances/<instance_id>/devtools/enable', methods=['POST'])
    @login_required
    def enable_devtools(instance_id):
        """启用实例的DevTools调试功能"""
        logger.info(f"API请求: 启用DevTools调试功能 - 实例ID: {instance_id}", "enable_devtools")
        
        # 获取实例
        instance = instance_pool.get_instance(instance_id)
        if not instance:
            logger.warning(f"实例不存在: {instance_id}", "enable_devtools")
            return jsonify({
                'success': False,
                'message': '实例不存在',
                'error_code': 'INSTANCE_NOT_FOUND'
            }), 404
        
        # 启用DevTools
        result = instance.enable_devtools()
        
        # 返回结果
        if result.get('success'):
            logger.info(f"DevTools调试功能启用成功: {instance_id}", "enable_devtools")
            return jsonify(result), 200
        else:
            logger.warning(f"DevTools调试功能启用失败: {instance_id}, {result.get('message')}", "enable_devtools")
            return jsonify(result), 400

    @app.route('/api/instances/<instance_id>/devtools/info', methods=['GET'])
    @login_required
    def get_devtools_info(instance_id):
        """获取实例的DevTools调试信息"""
        logger.debug(f"API请求: 获取DevTools调试信息 - 实例ID: {instance_id}", "get_devtools_info")
        
        # 获取实例
        instance = instance_pool.get_instance(instance_id)
        if not instance:
            logger.warning(f"实例不存在: {instance_id}", "get_devtools_info")
            return jsonify({
                'success': False,
                'message': '实例不存在',
                'error_code': 'INSTANCE_NOT_FOUND'
            }), 404
        
        # 获取DevTools信息
        result = instance.get_devtools_info()
        
        # 返回结果
        if result.get('success'):
            logger.debug(f"获取DevTools调试信息成功: {instance_id}", "get_devtools_info")
            return jsonify(result), 200
        else:
            logger.warning(f"获取DevTools调试信息失败: {instance_id}, {result.get('message')}", "get_devtools_info")
            return jsonify(result), 400

    @app.route('/api/instances/<instance_id>/devtools/connect', methods=['POST'])
    @login_required
    def create_devtools_connection(instance_id):
        """创建DevTools WebSocket连接"""
        logger.info(f"API请求: 创建DevTools WebSocket连接 - 实例ID: {instance_id}", "create_devtools_connection")
        
        # 获取实例
        instance = instance_pool.get_instance(instance_id)
        if not instance:
            logger.warning(f"实例不存在: {instance_id}", "create_devtools_connection")
            return jsonify({
                'success': False,
                'message': '实例不存在',
                'error_code': 'INSTANCE_NOT_FOUND'
            }), 404
        
        # 创建DevTools连接
        result = instance.create_devtools_connection()
        
        # 返回结果
        if result.get('success'):
            logger.info(f"DevTools WebSocket连接创建成功: {instance_id}", "create_devtools_connection")
            return jsonify(result), 200
        else:
            logger.warning(f"DevTools WebSocket连接创建失败: {instance_id}, {result.get('message')}", "create_devtools_connection")
            return jsonify(result), 400

    @app.route('/api/instances/<instance_id>/devtools/disable', methods=['POST'])
    @login_required
    def disable_devtools(instance_id):
        """禁用实例的DevTools调试功能"""
        logger.info(f"API请求: 禁用DevTools调试功能 - 实例ID: {instance_id}", "disable_devtools")
        
        # 获取实例
        instance = instance_pool.get_instance(instance_id)
        if not instance:
            logger.warning(f"实例不存在: {instance_id}", "disable_devtools")
            return jsonify({
                'success': False,
                'message': '实例不存在',
                'error_code': 'INSTANCE_NOT_FOUND'
            }), 404
        
        # 禁用DevTools
        result = instance.disable_devtools()
        
        # 返回结果
        if result.get('success'):
            logger.info(f"DevTools调试功能禁用成功: {instance_id}", "disable_devtools")
            return jsonify(result), 200
        else:
            logger.warning(f"DevTools调试功能禁用失败: {instance_id}, {result.get('message')}", "disable_devtools")
            return jsonify(result), 400

    # 添加一个API端点，用于设置浏览器初始URL
    @app.route('/api/config/browser-url', methods=['POST'])
    @login_required
    def set_browser_url():
        """设置浏览器初始URL"""
        logger.info(f"处理设置浏览器初始URL请求: {current_user.username}", "set_browser_url")
        
        try:
            # 检查用户权限
            if not auth_manager.check_user_permission('admin'):
                logger.warning(f"用户无权限设置浏览器URL: {current_user.username}", "set_browser_url")
                return jsonify({
                    'success': False,
                    'message': '权限不足，需要管理员权限'
                }), 403
            
            # 获取请求数据
            data = request.get_json()
            if not data or 'url' not in data:
                logger.warning("请求数据不完整，缺少URL参数", "set_browser_url")
                return jsonify({
                    'success': False,
                    'message': '请求数据不完整，缺少URL参数'
                }), 400
            
            new_url = data['url']
            
            # 验证URL格式
            if not new_url.startswith(('http://', 'https://')):
                logger.warning(f"URL格式无效: {new_url}", "set_browser_url")
                return jsonify({
                    'success': False,
                    'message': 'URL格式无效，必须以http://或https://开头'
                }), 400
            
            # 更新配置
            config_manager.update_config(telegram_url=new_url)
            
            logger.info(f"浏览器初始URL已更新: {new_url}", "set_browser_url")
            logger.operation("浏览器初始URL已更新", "set_browser_url", {
                'username': current_user.username,
                'new_url': new_url,
                'old_url': config_manager.get_config().telegram_url
            })
            
            return jsonify({
                'success': True,
                'message': '浏览器初始URL已更新',
                'url': new_url
            })
            
        except Exception as e:
            logger.error("设置浏览器初始URL时发生异常", "set_browser_url", e)
            return jsonify({
                'success': False,
                'message': f'设置浏览器初始URL时发生异常: {str(e)}'
            }), 500

    # 添加一个API端点，用于获取当前浏览器初始URL
    @app.route('/api/config/browser-url', methods=['GET'])
    @login_required
    def get_browser_url():
        """获取浏览器初始URL"""
        logger.info(f"处理获取浏览器初始URL请求: {current_user.username}", "get_browser_url")
        
        try:
            # 获取当前URL
            current_url = config_manager.get_config().telegram_url
            
            return jsonify({
                'success': True,
                'url': current_url
            })
            
        except Exception as e:
            logger.error("获取浏览器初始URL时发生异常", "get_browser_url", e)
            return jsonify({
                'success': False,
                'message': f'获取浏览器初始URL时发生异常: {str(e)}'
            }), 500

    logger.info("Web界面路由注册完成", "register_web_routes")

def render_fallback_login_page():
    """渲染备用登录页面"""
    logger.info("渲染备用登录页面", "render_fallback_login_page")
    
    # 简单的HTML登录页面
    fallback_html = '''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>系统登录</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #121212;
                color: #e0e0e0;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }
            .login-container {
                background: rgba(30, 30, 30, 0.9);
                border-radius: 10px;
                padding: 30px;
                box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
                width: 350px;
            }
            .login-title {
                text-align: center;
                margin-bottom: 30px;
                color: #00ff00;
                font-size: 24px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            .form-label {
                display: block;
                margin-bottom: 8px;
                color: #b0b0b0;
            }
            .form-input {
                width: 100%;
                padding: 12px;
                background: rgba(0, 0, 0, 0.7);
                border: 2px solid #333;
                border-radius: 5px;
                color: #e0e0e0;
                font-size: 16px;
                box-sizing: border-box;
            }
            .form-input:focus {
                outline: none;
                border-color: #00ff00;
            }
            .btn-login {
                width: 100%;
                padding: 12px;
                background: linear-gradient(135deg, #00ff00 0%, #00cc00 100%);
                color: #000;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                cursor: pointer;
            }
            .btn-login:hover {
                background: linear-gradient(135deg, #00cc00 0%, #009900 100%);
            }
            .error-message {
                color: #ff4444;
                text-align: center;
                margin-top: 15px;
                display: none;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1 class="login-title">系统登录</h1>
            <form id="login-form" method="post" action="/api/login">
                <div class="form-group">
                    <label for="username" class="form-label">用户名</label>
                    <input type="text" id="username" name="username" class="form-input" required>
                </div>
                <div class="form-group">
                    <label for="password" class="form-label">密码</label>
                    <input type="password" id="password" name="password" class="form-input" required>
                </div>
                <div class="form-group">
                    <button type="submit" class="btn-login">登录系统</button>
                </div>
                <div id="error-message" class="error-message"></div>
            </form>
        </div>
        
        <script>
            document.getElementById('login-form').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                try {
                    const response = await fetch('/api/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ username, password })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        window.location.href = '/dashboard';
                    } else {
                        document.getElementById('error-message').textContent = result.message || '登录失败';
                        document.getElementById('error-message').style.display = 'block';
                    }
                } catch (error) {
                    document.getElementById('error-message').textContent = '网络连接失败';
                    document.getElementById('error-message').style.display = 'block';
                }
            });
        </script>
    </body>
    </html>
    '''
    
    return fallback_html 