from flask import request, jsonify, session
from flask_login import current_user

from .logger import get_server_logger
from .auth import get_auth_manager

# 获取日志和认证实例
logger = get_server_logger()
auth_manager = get_auth_manager()


def setup_request_hooks(app):
    """注册全局请求钩子，提供：
    1. 每个请求的详细日志记录（方法 / 路径 / IP / token 信息等）
    2. 对所有 API* 请求统一执行令牌验证，及时发现并返回 401，防止未知状态下继续操作
       - 排除 /api/login 及 /api/logout（后者内部已处理）

    日志示例：
      [REQ] GET /api/instances from 127.0.0.1, token=abcd1234...
      [RESP] 200 GET /api/instances (duration=35ms)
    """

    @app.before_request
    def _before_request_logging():
        # 基本请求信息
        remote = request.remote_addr
        path = request.path
        method = request.method
        token_id = session.get('token_id')

        logger.debug(
            f"[REQ] {method} {path} from {remote}, token={str(token_id)[:8]}...",
            "request_hooks.before",
        )

        # 仅对 API 请求做统一验证，减少页面静态资源等开销
        if path.startswith('/api/') and path not in ['/api/login', '/api/logout']:
            header_token = request.headers.get('X-Auth-Token')
            if header_token:
                verify_result = auth_manager.verify_token_id(header_token)
            else:
                verify_result = auth_manager.verify_current_user()
            if not verify_result.get('success'):
                # 打印失败原因并返回
                logger.warning(
                    f"API 令牌验证失败: {verify_result.get('error_code')}",
                    "request_hooks.before",
                )
                return jsonify(verify_result), 401

    @app.after_request
    def _after_request_logging(response):
        # 输出响应日志
        logger.debug(
            f"[RESP] {request.method} {request.path} ==> {response.status_code}",
            "request_hooks.after",
        )
        return response 