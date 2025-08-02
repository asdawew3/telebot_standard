#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Flask应用主模块
负责创建Flask应用、注册路由、配置中间件等核心功能
提供完整的Web服务器和API接口支持
"""

import os
import sys
import time
import signal
import atexit
import platform
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_session import Session

from .config import get_config
from .auth import get_auth_manager, api_login_required, require_permission
from .logger import get_server_logger
from .instance_manager import instance_pool
from .profile_manager import profile_manager
from .web_routes import register_web_routes
from .js_manager import get_js_manager
from .network_manager import get_network_manager
from .chrome_network_fixer import get_chrome_network_fixer
from .request_hooks import setup_request_hooks

# 获取服务端日志实例
logger = get_server_logger()

def create_app() -> Flask:
    """
    创建Flask应用实例
    
    Returns:
        配置好的Flask应用实例
    """
    logger.info("开始创建Flask应用", "create_app")
    
    # 创建Flask应用实例
    app = Flask(__name__, 
                template_folder='templates',  # 模板文件夹
                static_folder='static')       # 静态文件夹
    
    logger.debug("Flask应用实例创建完成", "create_app")
    
    # 获取配置
    config = get_config()
    
    # 配置Flask
    app.config['SECRET_KEY'] = config.secret_key
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_FILE_DIR'] = 'flask_session'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = False  # 在开发环境中设为False
    
    logger.debug("Flask基础配置完成", "create_app")
    
    # 初始化扩展
    logger.debug("初始化Flask扩展", "create_app")
    
    # 启用CORS支持
    CORS(app, supports_credentials=True)
    logger.debug("CORS支持已启用", "create_app")
    
    # 初始化会话管理
    Session(app)
    logger.debug("会话管理已初始化", "create_app")
    
    # 初始化认证管理器
    auth_manager = get_auth_manager()
    auth_manager.init_app(app)
    logger.debug("认证管理器已初始化", "create_app")
    
    # 注册全局请求钩子（日志 + 统一令牌验证）
    setup_request_hooks(app)
    logger.debug("请求钩子已注册", "create_app")
    
    # 注册路由
    logger.debug("开始注册应用路由", "create_app")
    register_api_routes(app)      # API路由
    register_web_routes(app)      # Web页面路由
    logger.debug("应用路由注册完成", "create_app")
    
    logger.info("Flask应用创建完成", "create_app")
    return app

def register_api_routes(app: Flask):
    """
    注册API路由
    
    Args:
        app: Flask应用实例
    """
    logger.info("开始注册API路由", "register_api_routes")
    
    # 获取认证管理器
    auth_manager = get_auth_manager()
    # api_login_required和require_permission已在顶部导入
    
    # ================================
    # 认证相关API路由
    # ================================
    
    @app.route('/api/login', methods=['POST'])
    def login():
        """用户登录API"""
        logger.info("处理用户登录请求", "login")
        
        try:
            # 获取请求数据
            data = request.get_json()
            if not data:
                logger.warning("登录请求数据为空", "login")
                return jsonify({
                    'success': False,
                    'message': '请求数据无效'
                }), 400
            
            # 提取用户名和密码
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                logger.warning(f"登录凭据不完整: username={bool(username)}, password={bool(password)}", "login")
                return jsonify({
                    'success': False,
                    'message': '用户名和密码不能为空'
                }), 400
            
            logger.debug(f"尝试登录用户: {username}", "login")
            
            # 执行登录验证（stateless 控制）
            stateless = bool(data.get('stateless'))
            login_result = auth_manager.login_user(username, password)
            
            if login_result['success']:
                logger.info(f"用户登录成功: {username}", "login")
                response = jsonify({
                    'success': True,
                    'message': '登录成功',
                    'token': login_result.get('token'),
                    'user': login_result.get('user', {})
                })
                if stateless:
                    # 清除 Flask session，以免写 Cookie
                    session.clear()
                    response.set_cookie('session', '', expires=0)
                return response, 200
            else:
                logger.warning(f"用户登录失败: {username} - {login_result.get('message')}", "login")
                return jsonify({
                    'success': False,
                    'message': login_result.get('message', '登录失败')
                }), 401
                
        except Exception as e:
            logger.error("处理登录请求发生异常", "login", e)
            return jsonify({
                'success': False,
                'message': '登录失败'
            }), 500
    
    @app.route('/api/logout', methods=['POST'])
    @api_login_required
    def logout():
        """用户注销API"""
        logger.info("处理用户注销请求", "logout")
        
        try:
            # 执行注销操作
            logout_result = auth_manager.logout_user()
            
            if logout_result['success']:
                logger.info("用户注销成功", "logout")
                return jsonify({
                    'success': True,
                    'message': '注销成功'
                }), 200
            else:
                logger.warning(f"用户注销失败: {logout_result.get('message')}", "logout")
                return jsonify({
                    'success': False,
                    'message': logout_result.get('message', '注销失败')
                }), 500
                
        except Exception as e:
            logger.error("处理注销请求发生异常", "logout", e)
            return jsonify({
                'success': False,
                'message': '注销失败'
            }), 500
    
    @app.route('/api/verify-token', methods=['GET'])
    @api_login_required
    def verify_token():
        """验证用户令牌API"""
        logger.debug("处理令牌验证请求", "verify_token")
        
        try:
            # 获取当前用户信息
            user_info = auth_manager.get_current_user_info()
            
            logger.debug(f"令牌验证成功: {user_info.get('username')}", "verify_token")
            return jsonify({
                'success': True,
                'message': '令牌有效',
                'user': user_info
            }), 200
            
        except Exception as e:
            logger.error("处理令牌验证请求发生异常", "verify_token", e)
            return jsonify({
                'success': False,
                'message': '令牌验证失败'
            }), 401
    
    # ================================
    # 分组管理API路由
    # ================================
    
    @app.route('/api/groups', methods=['GET'])
    @api_login_required
    @require_permission('view')
    def list_groups():
        """获取分组列表"""
        logger.info("处理获取分组列表请求", "list_groups")
        
        try:
            # 返回默认分组列表
            groups = [
                {'id': 'default', 'name': '默认分组', 'description': '系统默认分组'},
                {'id': 'test', 'name': '测试分组', 'description': '用于测试的分组'},
                {'id': 'production', 'name': '生产分组', 'description': '生产环境分组'}
            ]
            
            logger.info(f"获取分组列表成功，数量: {len(groups)}", "list_groups")
            return jsonify({
                'success': True,
                'data': groups,
                'total': len(groups)
            }), 200
            
        except Exception as e:
            logger.error("获取分组列表失败", "list_groups", e)
            return jsonify({
                'success': False,
                'message': '获取分组列表失败'
            }), 500
    
    @app.route('/api/groups', methods=['POST'])
    @api_login_required
    @require_permission('manage')
    def create_group():
        """创建新分组"""
        logger.info("处理创建分组请求", "create_group")
        
        try:
            # 获取请求数据
            data = request.get_json()
            if not data:
                logger.warning("创建分组请求数据为空", "create_group")
                return jsonify({
                    'success': False,
                    'message': '请求数据无效'
                }), 400
            
            # 提取分组信息
            group_name = data.get('name', '').strip()
            group_description = data.get('description', '').strip()
            
            if not group_name:
                logger.warning("分组名称不能为空", "create_group")
                return jsonify({
                    'success': False,
                    'message': '分组名称不能为空'
                }), 400
            
            logger.debug(f"创建分组: {group_name}", "create_group")
            
            # 模拟创建分组成功
            logger.info(f"分组创建成功: {group_name}", "create_group")
            return jsonify({
                'success': True,
                'message': '分组创建成功',
                'group': {
                    'id': group_name.lower().replace(' ', '_'),
                    'name': group_name,
                    'description': group_description
                }
            }), 201
                
        except Exception as e:
            logger.error("处理创建分组请求发生异常", "create_group", e)
            return jsonify({
                'success': False,
                'message': '分组创建失败'
            }), 500
    
    @app.route('/api/groups/<group_id>', methods=['DELETE'])
    @api_login_required
    @require_permission('manage')
    def delete_group(group_id):
        """删除分组"""
        logger.info(f"处理删除分组请求: {group_id}", "delete_group")
        
        try:
            # 检查是否为保护的分组
            if group_id in ['default', 'test', 'production']:
                logger.warning(f"不能删除系统分组: {group_id}", "delete_group")
                return jsonify({
                    'success': False,
                    'message': f'不能删除系统分组: {group_id}'
                }), 400
            
            # 模拟删除分组成功
            logger.info(f"分组删除成功: {group_id}", "delete_group")
            return jsonify({
                'success': True,
                'message': '分组删除成功'
            }), 200
                
        except Exception as e:
            logger.error(f"处理删除分组请求发生异常: {group_id}", "delete_group", e)
            return jsonify({
                'success': False,
                'message': '分组删除失败'
            }), 500
    
    # ================================
    # 用户资料管理API路由
    # ================================
    
    @app.route('/api/profiles', methods=['GET'])
    @api_login_required
    @require_permission('view')
    def list_profiles():
        """获取用户资料列表"""
        logger.info("处理获取用户资料列表请求", "list_profiles")
        
        try:
            # 获取查询参数
            group_id = request.args.get('group_id')
            
            # 获取用户资料列表
            profiles = profile_manager.list_profiles()
            
            logger.info(f"获取用户资料列表成功，数量: {len(profiles)}", "list_profiles")
            return jsonify({
                'success': True,
                'data': profiles,
                'total': len(profiles)
            }), 200
            
        except Exception as e:
            logger.error("获取用户资料列表失败", "list_profiles", e)
            return jsonify({
                'success': False,
                'message': '获取用户资料列表失败'
            }), 500
    
    @app.route('/api/profiles', methods=['POST'])
    @api_login_required
    @require_permission('manage')
    def create_profile():
        """创建新用户资料"""
        logger.info("处理创建用户资料请求", "create_profile")
        
        try:
            # 获取请求数据
            data = request.get_json()
            if not data:
                logger.warning("创建用户资料请求数据为空", "create_profile")
                return jsonify({
                    'success': False,
                    'message': '请求数据无效'
                }), 400
            
            # 提取资料信息
            profile_name = data.get('name', '').strip()
            group_id = data.get('group_id', 'default').strip()
            profile_data = data.get('profile_data', {})
            
            if not profile_name:
                logger.warning("用户资料名称不能为空", "create_profile")
                return jsonify({
                    'success': False,
                    'message': '用户资料名称不能为空'
                }), 400
            
            logger.debug(f"创建用户资料: {profile_name}, 分组: {group_id}", "create_profile")
            
            # 创建用户资料
            result = profile_manager.create_profile(
                name=profile_name,
                description=f"通过API创建于 {group_id} 分组",
                tags=[group_id] if group_id != 'default' else []
            )
            
            if result['success']:
                logger.info(f"用户资料创建成功: {profile_name}", "create_profile")
                return jsonify({
                    'success': True,
                    'message': '用户资料创建成功',
                    'profile': result.get('profile')
                }), 201
            else:
                logger.warning(f"用户资料创建失败: {profile_name} - {result.get('message')}", "create_profile")
                return jsonify({
                    'success': False,
                    'message': result.get('message', '用户资料创建失败')
                }), 400
                
        except Exception as e:
            logger.error("处理创建用户资料请求发生异常", "create_profile", e)
            return jsonify({
                'success': False,
                'message': '用户资料创建失败'
            }), 500
    
    @app.route('/api/profiles/<profile_id>', methods=['DELETE'])
    @api_login_required
    @require_permission('manage')
    def delete_profile(profile_id):
        """删除用户资料"""
        logger.info(f"处理删除用户资料请求: {profile_id}", "delete_profile")
        
        try:
            # 删除用户资料
            result = profile_manager.delete_profile(profile_id)
            
            if result['success']:
                logger.info(f"用户资料删除成功: {profile_id}", "delete_profile")
                return jsonify({
                    'success': True,
                    'message': '用户资料删除成功'
                }), 200
            else:
                logger.warning(f"用户资料删除失败: {profile_id} - {result.get('message')}", "delete_profile")
                return jsonify({
                    'success': False,
                    'message': result.get('message', '用户资料删除失败')
                }), 400
                
        except Exception as e:
            logger.error(f"处理删除用户资料请求发生异常: {profile_id}", "delete_profile", e)
            return jsonify({
                'success': False,
                'message': '用户资料删除失败'
            }), 500
    
    # ================================
    # 实例管理API路由
    # ================================
    
    @app.route('/api/instances', methods=['GET'])
    @api_login_required
    @require_permission('view')
    def list_instances():
        """获取实例列表"""
        logger.info("处理获取实例列表请求", "list_instances")
        
        try:
            # 获取查询参数
            group_id = request.args.get('group_id')
            
            # 获取实例列表
            instances = instance_pool.list_instances(group_id)
            
            logger.info(f"获取实例列表成功，数量: {len(instances)}", "list_instances")
            return jsonify({
                'success': True,
                'data': instances,
                'total': len(instances)
            }), 200
            
        except Exception as e:
            logger.error("获取实例列表失败", "list_instances", e)
            return jsonify({
                'success': False,
                'message': '获取实例列表失败'
            }), 500
    
    @app.route('/api/instances', methods=['POST'])
    @api_login_required
    @require_permission('create')
    def create_instance():
        """创建新实例"""
        logger.info("处理创建实例请求", "create_instance")
        
        try:
            # 获取请求数据
            data = request.get_json() or {}
            
            # 提取实例信息
            instance_name = data.get('name', '').strip()
            group_id = data.get('group_id', 'default').strip()
            profile_id = data.get('profile_id', 'default').strip()
            
            logger.debug(f"创建实例: name={instance_name}, group={group_id}, profile={profile_id}", "create_instance")
            
            # 创建实例
            result = instance_pool.create_instance(instance_name, group_id, profile_id)
            
            if result['success']:
                logger.info(f"实例创建成功: {result.get('instance_id')}", "create_instance")
                return jsonify({
                    'success': True,
                    'message': '实例创建成功',
                    'instance': result.get('instance')
                }), 201
            else:
                logger.warning(f"实例创建失败: {result.get('message')}", "create_instance")
                return jsonify({
                    'success': False,
                    'message': result.get('message', '实例创建失败')
                }), 400
                
        except Exception as e:
            logger.error("处理创建实例请求发生异常", "create_instance", e)
            return jsonify({
                'success': False,
                'message': '实例创建失败'
            }), 500
    
    @app.route('/api/instances/<instance_id>', methods=['DELETE'])
    @api_login_required
    @require_permission('all')
    def destroy_instance(instance_id):
        """销毁实例"""
        logger.info(f"处理销毁实例请求: {instance_id}", "destroy_instance")
        
        try:
            # 销毁实例
            result = instance_pool.destroy_instance(instance_id)
            
            if result['success']:
                logger.info(f"实例销毁成功: {instance_id}", "destroy_instance")
                return jsonify({
                    'success': True,
                    'message': '实例销毁成功'
                }), 200
            else:
                logger.warning(f"实例销毁失败: {instance_id} - {result.get('message')}", "destroy_instance")
                return jsonify({
                    'success': False,
                    'message': result.get('message', '实例销毁失败')
                }), 400
                
        except Exception as e:
            logger.error(f"处理销毁实例请求发生异常: {instance_id}", "destroy_instance", e)
            return jsonify({
                'success': False,
                'message': '实例销毁失败'
            }), 500
    
    # ================================
    # JavaScript注入和命令执行API路由
    # ================================
    
    @app.route('/api/instances/<instance_id>/inject', methods=['POST', 'GET'])
    @api_login_required
    @require_permission('execute')
    def inject_javascript(instance_id):
        """注入JavaScript"""
        logger.info(f"处理JavaScript注入请求: {instance_id}", "inject_javascript")
        
        try:
            # 获取实例
            instance = instance_pool.get_instance(instance_id)
            if not instance:
                logger.warning(f"实例不存在: {instance_id}", "inject_javascript")
                return jsonify({
                    'success': False,
                    'message': '实例不存在'
                }), 404
            
            # 对 GET 方法或无 JSON 的 POST，执行批量注入
            file_path = None
            if request.method == 'POST':
                try:
                    data = request.get_json(silent=True) or {}
                    file_path = data.get('file_path')
                except Exception:
                    # 若解析出错，回退批量注入
                    file_path = None
            
            logger.debug(f"JavaScript注入参数: 实例={instance_id}, 文件={file_path}", "inject_javascript")
            
            # 执行JavaScript注入
            success = instance.inject_javascript(file_path)
            
            # 返回注入结果
            if success:
                logger.info(f"JavaScript注入成功: {instance_id}", "inject_javascript")
                return jsonify({
                    'success': True,
                    'message': 'JavaScript注入成功'
                }), 200
            else:
                logger.warning(f"JavaScript注入失败: {instance_id}", "inject_javascript")
                return jsonify({
                    'success': False,
                    'message': 'JavaScript注入失败'
                }), 500
                
        except Exception as e:
            logger.error(f"处理JavaScript注入请求发生异常: {instance_id}", "inject_javascript", e)
            return jsonify({
                'success': False,
                'message': 'JavaScript注入失败'
            }), 500
    
    @app.route('/api/instances/<instance_id>/execute', methods=['POST'])
    @api_login_required
    @require_permission('execute')
    def execute_command(instance_id):
        """执行JavaScript命令"""
        logger.info(f"处理命令执行请求: {instance_id}", "execute_command")
        
        try:
            # 获取实例
            instance = instance_pool.get_instance(instance_id)
            if not instance:
                logger.warning(f"实例不存在: {instance_id}", "execute_command")
                return jsonify({
                    'success': False,
                    'message': '实例不存在'
                }), 404
            
            # 获取请求数据
            data = request.get_json()
            if not data:
                logger.warning(f"命令执行请求数据为空: {instance_id}", "execute_command")
                return jsonify({
                    'success': False,
                    'message': '请求数据无效'
                }), 400
            
            # 提取命令和参数
            command = data.get('command', '').strip()
            args = data.get('args', [])
            
            if not command:
                logger.warning(f"命令执行缺少命令参数: {instance_id}", "execute_command")
                return jsonify({
                    'success': False,
                    'message': '命令不能为空'
                }), 400
            
            logger.debug(f"执行命令: 实例={instance_id}, 命令={command}, 参数={args}", "execute_command")
            
            # 执行命令
            result = instance.execute_command(command, args)
            
            # 返回执行结果
            if result['success']:
                logger.info(f"命令执行成功: {instance_id}, 命令={command}", "execute_command")
                return jsonify(result), 200
            else:
                logger.warning(f"命令执行失败: {instance_id}, 命令={command}, 原因={result.get('message')}", "execute_command")
                return jsonify(result), 500
                
        except Exception as e:
            logger.error(f"处理命令执行请求发生异常: {instance_id}", "execute_command", e)
            return jsonify({
                'success': False,
                'message': '命令执行失败'
            }), 500
    
    # ================================
    # JavaScript模块管理API路由
    # ================================
    
    @app.route('/api/js-modules', methods=['GET'])
    @api_login_required
    @require_permission('view')
    def list_js_modules():
        """获取JavaScript模块列表"""
        logger.info("处理获取JavaScript模块列表请求", "list_js_modules")
        
        try:
            # 获取JavaScript模块管理器
            js_manager = get_js_manager()
            
            # 获取JavaScript模块列表
            modules = js_manager.list_modules()
            
            logger.info(f"获取JavaScript模块列表成功，数量: {len(modules)}", "list_js_modules")
            return jsonify({
                'success': True,
                'data': modules,
                'total': len(modules)
            }), 200
            
        except Exception as e:
            logger.error("获取JavaScript模块列表失败", "list_js_modules", e)
            return jsonify({
                'success': False,
                'message': f'获取JavaScript模块列表失败: {str(e)}',
                'error_code': 'LIST_JS_MODULES_ERROR'
            }), 500
    
    # ================================
    # 网络管理API路由
    # ================================
    
    @app.route('/api/network/status', methods=['GET'])
    @api_login_required
    @require_permission('view')
    def network_status():
        """获取网络状态"""
        logger.info("处理网络状态查询请求", "network_status")
        
        try:
            # 获取配置信息
            config = get_config()
            
            # 获取网络管理器
            network_manager = get_network_manager()
            
            # 检查端口状态
            logger.debug(f"检查端口状态: {config.port}", "network_status")
            port_status = network_manager.check_port_accessibility(config.port)
            
            # 构建网络状态响应
            status = {
                'port': config.port,
                'host': config.host,
                'local_ip': port_status.get('local_ip', '未知'),
                'is_listening': port_status.get('is_listening', False),
                'can_bind': port_status.get('can_bind', False),
                'external_accessible': config.host == '0.0.0.0',
                'suggestions': port_status.get('suggestions', []),
                'timestamp': time.time()
            }
            
            logger.info(f"网络状态查询成功: 端口={config.port}, 监听={status['is_listening']}", "network_status")
            return jsonify({
                'success': True,
                'network_status': status
            }), 200
            
        except Exception as e:
            logger.error("获取网络状态失败", "network_status", e)
            return jsonify({
                'success': False,
                'message': '获取网络状态失败'
            }), 500
    
    @app.route('/api/network/configure', methods=['POST'])
    @api_login_required
    @require_permission('admin')
    def configure_network():
        """配置网络和防火墙"""
        logger.info("处理网络配置请求", "configure_network")
        
        try:
            # 获取配置信息
            config = get_config()
            
            # 获取网络管理器
            network_manager = get_network_manager()
            
            # 配置防火墙
            logger.debug(f"配置防火墙: 端口={config.port}", "configure_network")
            firewall_result = network_manager.configure_firewall(config.port)
            
            logger.info(f"防火墙配置完成: 成功={firewall_result.get('success', False)}", "configure_network")
            return jsonify({
                'success': firewall_result.get('success', False),
                'message': firewall_result.get('message', '配置完成'),
                'commands': firewall_result.get('commands', []),
                'timestamp': time.time()
            }), 200
            
        except Exception as e:
            logger.error("网络配置失败", "configure_network", e)
            return jsonify({
                'success': False,
                'message': f'网络配置失败: {str(e)}'
            }), 500
    
    # ================================
    # 系统状态API路由
    # ================================
    
    @app.route('/api/status', methods=['GET'])
    def server_status():
        """获取服务器状态信息"""
        logger.info("获取服务器状态信息", "server_status")
        
        try:
            # 获取配置
            config = get_config()
            
            # 获取实例信息
            instances = instance_pool.list_instances()
            
            # 获取网络状态
            network_manager = get_network_manager()
            port_status = network_manager.check_port_accessibility(config.port)
            
            # 构建状态信息
            status = {
                'server': {
                    'version': '2.0.0',
                    'uptime': time.time() - config.start_time,
                    'port': config.port,
                    'host': config.host,
                    'debug': config.debug,
                    'max_instances': config.max_instances,
                    'log_level': config.log_level
                },
                'instances': {
                    'total': len(instances),
                    'active': sum(1 for i in instances if i['status'] == 'ready'),
                    'error': sum(1 for i in instances if i['status'] == 'error'),
                    'initializing': sum(1 for i in instances if i['status'] == 'initializing')
                },
                'network': {
                    'local_ip': port_status.get('local_ip', '127.0.0.1'),
                    'port_accessible': port_status.get('can_bind', False),
                    'port_in_use': port_status.get('is_listening', False)
                },
                'system': {
                    'platform': platform.system(),
                    'platform_version': platform.version(),
                    'python_version': platform.python_version(),
                    'processor': platform.processor()
                }
            }
            
            logger.info("服务器状态信息获取成功", "server_status")
            return jsonify({
                'success': True,
                'data': status
            }), 200
            
        except Exception as e:
            logger.error("获取服务器状态信息失败", "server_status", e)
            return jsonify({
                'success': False,
                'message': '获取服务器状态信息失败',
                'error': str(e)
            }), 500
    
    logger.info("API路由注册完成", "register_api_routes")

def cleanup_on_exit():
    """程序退出时的清理操作"""
    logger.info("执行程序退出清理操作", "cleanup_on_exit")
    
    try:
        # 关闭实例池
        instance_pool.shutdown()
        logger.info("实例池关闭完成", "cleanup_on_exit")
        
    except Exception as e:
        logger.error("执行清理操作发生异常", "cleanup_on_exit", e)

def run_server():
    """运行服务器"""
    logger.info("启动Telegram Bot服务器", "run_server")
    
    try:
        # 创建Flask应用
        app = create_app()
        
        # 获取配置
        config = get_config()
        
        # 启动服务器
        logger.info(f"服务器启动在 http://{config.host}:{config.port}", "run_server")
        
        try:
            app.run(
                host=config.host,
                port=config.port,
                debug=config.debug,
                threaded=True,  # 启用多线程支持
                use_reloader=False  # 禁用自动重载（避免日志重复）
            )
            
        except OSError as e:
            if e.errno == 10048:  # Windows: Address already in use
                logger.error(f"端口 {config.port} 被占用 (Windows错误码: 10048)", "run_server")
                logger.error("可能的解决方案:", "run_server")
                logger.error("1. 检查是否有其他程序占用了该端口", "run_server")
                logger.error("2. 等待几分钟后重试", "run_server")
                logger.error("3. 修改配置文件中的端口号", "run_server")
                logger.error("4. 重启计算机以清理所有网络连接", "run_server")
                raise
            elif e.errno == 98:   # Linux: Address already in use
                logger.error(f"端口 {config.port} 被占用 (Linux错误码: 98)", "run_server")
                logger.error("可能的解决方案:", "run_server")
                logger.error("1. 使用 lsof -i :5000 查看占用端口的进程", "run_server")
                logger.error("2. 使用 kill -9 <PID> 终止占用进程", "run_server")
                logger.error("3. 修改配置文件中的端口号", "run_server")
                raise
            elif e.errno == 13:   # Permission denied
                logger.error(f"权限不足，无法绑定端口 {config.port}", "run_server")
                logger.error("可能的解决方案:", "run_server")
                logger.error("1. 使用管理员权限运行程序", "run_server")
                logger.error("2. 选择大于1024的端口号", "run_server")
                raise
            else:
                logger.error(f"网络错误 (错误码: {e.errno}): {e}", "run_server")
                raise
                
        except Exception as e:
            logger.error(f"Flask服务器启动异常: {e}", "run_server", e)
            raise
        
    except Exception as e:
        logger.error("服务器启动失败", "run_server", e)
        raise

if __name__ == '__main__':
    run_server() 