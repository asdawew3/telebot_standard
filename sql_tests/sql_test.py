#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
简单SQL Server ODBC连接测试
"""

import os
import json
import sys

def load_config():
    """从父目录加载配置"""
    try:
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
                return config_data.get('database', {})
    except Exception as e:
        print(f"[WARNING] 无法加载配置文件: {e}")
    
    # 默认配置
    return {
        "server": "127.0.0.1",
        "database": "。。。",
        "username": "sa",
        "password": "123456",
        "driver": "{ODBC Driver 17 for SQL Server}",
        "table_name": "。。。",
        "use_windows_auth": False
    }

def test_sql_connection():
    """测试SQL Server连接"""
    print("=" * 50)
    print("SQL Server ODBC 连接测试")
    print("=" * 50)
    
    # 检查pyodbc
    try:
        import pyodbc
        print("[OK] pyodbc 库已安装")
    except ImportError:
        print("[ERROR] pyodbc 库未安装")
        print("请运行: pip install pyodbc")
        return False
    
    # 加载配置
    config = load_config()
    print(f"[INFO] 服务器: {config['server']}")
    print(f"[INFO] 目标数据库: {config['database']}")
    print(f"[INFO] 用户名: {config['username']}")
    print(f"[INFO] 驱动: {config['driver']}")
    print(f"[INFO] 认证方式: {'Windows认证' if config['use_windows_auth'] else 'SQL认证'}")
    print("-" * 50)
    
    # 检查ODBC驱动
    print("[INFO] 检查ODBC驱动...")
    try:
        all_drivers = pyodbc.drivers()
        sql_drivers = [d for d in all_drivers if 'SQL' in d.upper()]
        
        if not sql_drivers:
            print("[ERROR] 未找到SQL Server驱动")
            return False
        
        print(f"[OK] 找到 {len(sql_drivers)} 个SQL Server驱动")
        for driver in sql_drivers:
            print(f"      - {driver}")
        
        # 检查配置的驱动
        driver_name = config['driver'].strip('{}')
        if driver_name not in all_drivers:
            print(f"[WARNING] 配置的驱动不存在，使用第一个可用驱动")
            config['driver'] = f"{{{sql_drivers[0]}}}"
        
    except Exception as e:
        print(f"[ERROR] 驱动检查失败: {e}")
        return False
    
    print("-" * 50)
    
    # 先测试连接到master数据库
    print("[INFO] 测试连接到master数据库...")
    
    # 构建连接字符串 - 先连接master
    if config['use_windows_auth']:
        conn_str = f"DRIVER={config['driver']};SERVER={config['server']};DATABASE=master;Trusted_Connection=yes;"
    else:
        conn_str = f"DRIVER={config['driver']};SERVER={config['server']};DATABASE=master;UID={config['username']};PWD={config['password']};"
    
    try:
        # 尝试连接master
        conn = pyodbc.connect(conn_str, timeout=10)
        print("[OK] 连接到master数据库成功!")
        
        # 基本查询测试
        cursor = conn.cursor()
        cursor.execute("SELECT DB_NAME(), @@SERVERNAME, @@VERSION")
        db_name, server_name, version = cursor.fetchone()
        
        print(f"[INFO] 当前数据库: {db_name}")
        print(f"[INFO] 服务器名: {server_name}")
        print(f"[INFO] 版本: {version.split()[0]} {version.split()[1]} {version.split()[2]}")
        
        # 列出所有数据库
        print(f"[INFO] 列出所有数据库:")
        cursor.execute("SELECT name FROM sys.databases WHERE state = 0 ORDER BY name")
        databases = [row[0] for row in cursor.fetchall()]
        
        target_db_found = False
        for db in databases:
            if db == config['database']:
                print(f"      - {db} [目标数据库]")
                target_db_found = True
            else:
                print(f"      - {db}")
        
        cursor.close()
        conn.close()
        
        if not target_db_found:
            print(f"[WARNING] 目标数据库 '{config['database']}' 不存在")
            print(f"[INFO] 请检查数据库名称是否正确")
            return False
        
        print("-" * 50)
        
        # 现在测试连接到目标数据库
        print(f"[INFO] 测试连接到目标数据库: {config['database']}")
        
        if config['use_windows_auth']:
            target_conn_str = f"DRIVER={config['driver']};SERVER={config['server']};DATABASE={config['database']};Trusted_Connection=yes;"
        else:
            target_conn_str = f"DRIVER={config['driver']};SERVER={config['server']};DATABASE={config['database']};UID={config['username']};PWD={config['password']};"
        
        try:
            target_conn = pyodbc.connect(target_conn_str, timeout=10)
            print(f"[OK] 连接到 '{config['database']}' 数据库成功!")
            
            cursor = target_conn.cursor()
            
            # 检查目标表
            table_name = config['table_name']
            print(f"[INFO] 检查目标表: {table_name}")
            cursor.execute("""
                SELECT COUNT(*) 
                FROM INFORMATION_SCHEMA.TABLES 
                WHERE TABLE_NAME = ?
            """, table_name)
            
            table_exists = cursor.fetchone()[0] > 0
            
            if table_exists:
                print(f"[OK] 表 '{table_name}' 存在")
                
                # 统计记录数
                cursor.execute(f"SELECT COUNT(*) FROM [{table_name}]")
                record_count = cursor.fetchone()[0]
                print(f"[INFO] 记录数: {record_count:,}")
                
            else:
                print(f"[WARNING] 表 '{table_name}' 不存在")
                
                # 列出前10个表
                cursor.execute("""
                    SELECT TOP 10 TABLE_NAME 
                    FROM INFORMATION_SCHEMA.TABLES 
                    WHERE TABLE_TYPE = 'BASE TABLE'
                    ORDER BY TABLE_NAME
                """)
                tables = [row[0] for row in cursor.fetchall()]
                if tables:
                    print("[INFO] 数据库中的表:")
                    for table in tables:
                        print(f"        - {table}")
            
            cursor.close()
            target_conn.close()
            
            print("-" * 50)
            print("[SUCCESS] 连接测试完成 - 所有功能正常")
            return True
            
        except Exception as e:
            print(f"[ERROR] 连接目标数据库失败: {e}")
            return False
        
    except Exception as e:
        print(f"[ERROR] 连接master数据库失败: {e}")
        print("-" * 50)
        print("[INFO] 可能的解决方案:")
        print("  1. 检查服务器地址和端口")
        print("  2. 检查用户名和密码")
        print("  3. 检查SQL Server服务是否运行")
        print("  4. 检查防火墙设置")
        print("  5. 检查SQL Server是否允许远程连接")
        print("  6. 检查sa账户是否启用")
        return False

if __name__ == '__main__':
    success = test_sql_connection()
    print("\n" + "=" * 50)
    if success:
        print("[RESULT] SQL Server连接测试通过")
    else:
        print("[RESULT] SQL Server连接测试失败")
    print("=" * 50)
    sys.exit(0 if success else 1) 