# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Telegram automation system built with Flask that provides web interfaces for managing Chrome browser instances to interact with Telegram Web. The system consists of a server component for management and a client component for user operations.

## System Architecture

### Core Components

- **Server (`server/`)**: Flask-based management backend with authentication, instance management, and API endpoints
- **Client (`client/`)**: Web interface for end-user operations and interaction with Telegram
- **Profile Management**: Browser profile management for multiple user sessions
- **Instance Pool**: Manages multiple Chrome browser instances with Selenium WebDriver
- **JavaScript Injection**: System for injecting custom scripts into Telegram Web pages

### Key Files

- `start_system.py`: Main system launcher that starts both server and client
- `server.py`: Server entry point with Flask application initialization
- `client_web.py`: Client web application entry point
- `server/app.py`: Core Flask application with all API routes and web routes
- `server/instance_manager.py`: Manages Chrome instances and their lifecycle
- `server/config.py`: Centralized configuration management
- `server/auth.py`: Authentication and authorization system

## Development Commands

### Starting the System

```bash
# Start both server and client (recommended)
python start_system.py

# Start server only
python server.py

# Start client only
python client_web.py --port 5001 --server-url http://127.0.0.1:5000
```

### Dependencies

```bash
# Install dependencies
pip install -r requirements.txt
```

### Configuration

- Server configuration: `config.json` (auto-generated with defaults)
- Client configuration: `client_config.json`
- Default server port: 5000
- Default client port: 5001
- Default credentials: 10086 / Kx7#mP9$nL2@wZ8!qR4%fH6^dG1&yU3*

## Code Architecture Details

### Authentication System
The system uses Flask-Login with token-based authentication. All API endpoints require authentication via `@api_login_required` decorator and permission-based access control via `@require_permission()`.

### Instance Management
Browser instances are managed through a pool system (`instance_pool`) that handles:
- Chrome instance lifecycle (create, monitor, destroy)
- Profile assignment and management
- JavaScript injection and command execution
- Resource cleanup and timeout handling

### Configuration Management
Centralized configuration via `ServerConfig` dataclass with automatic validation and file persistence. Key settings include ports, timeouts, instance limits, and security parameters.

### JavaScript Module System
The system loads and injects JavaScript modules from the `js_modules/` directory into Telegram Web pages for automation tasks.

### Network Management
Built-in network utilities for port checking, firewall configuration, and accessibility testing.

### Logging System
Comprehensive logging with structured format, automatic log rotation, and separate loggers for different components (server, client, instances).

## Directory Structure

```
telebot_standard/
├── server/           # Server backend modules
├── client/           # Client web application
├── js_modules/       # JavaScript files for injection
├── profiles/         # Browser profiles storage
├── logs/             # System logs
├── templates/        # Web page templates
├── flask_session/    # Flask session storage
└── 风格/             # UI style templates
```

## Key Patterns

- All server modules use centralized logging via `get_server_logger()`
- Configuration is accessed via `get_config()` throughout the system
- API responses follow consistent `{'success': bool, 'message': str, 'data': any}` format
- Instance operations are handled through the global `instance_pool` object
- Authentication state is managed via Flask session and custom token system

## Important Notes

- The system requires Chrome/Chromium browser for Selenium WebDriver operations
- JavaScript files in `js_modules/` are automatically loaded and available for injection
- Browser profiles are isolated in the `profiles/` directory for security
- All network operations include proper error handling and logging
- The system includes built-in port conflict resolution and cleanup mechanisms