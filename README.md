# Web3 PAM Authentication System

一个基于Web3钱包签名验证的PAM（Pluggable Authentication Module）认证系统，允许用户使用以太坊钱包进行系统登录。

## 功能特性

- 🔐 **Web3钱包认证**: 使用以太坊钱包私钥进行签名验证
- 🛡️ **安全挑战机制**: 服务器生成随机挑战，防止重放攻击
- ⚡ **高性能**: 基于C语言实现，性能优异
- 🔧 **易于集成**: 标准PAM模块，可轻松集成到现有系统
- 📡 **RESTful API**: 提供HTTP API接口进行认证服务
- 🎯 **跨平台**: 支持Linux系统

## 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PAM Module    │    │  Auth Server    │    │  Web3 Wallet    │
│                 │    │                 │    │                 │
│ 1. 获取挑战     │───▶│ 2. 生成挑战     │    │ 3. 签名挑战     │
│ 4. 验证签名     │◀───│ 5. 验证结果     │◀───│                 │
│ 6. 登录成功     │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 认证流程

1. **用户登录**: 用户尝试登录系统
2. **获取挑战**: PAM模块向认证服务器请求签名挑战
3. **钱包签名**: 用户使用Web3钱包对挑战进行签名
4. **验证签名**: 服务器验证签名的有效性
5. **登录成功**: 验证通过后允许用户登录

## 安装要求

### 系统依赖

- Linux操作系统
- GCC编译器
- PAM开发库
- OpenSSL开发库
- JSON-C库
- libcurl库

### Ubuntu/Debian安装依赖

```bash
sudo apt-get update
sudo apt-get install -y build-essential libpam0g-dev libssl-dev libjson-c-dev libcurl4-openssl-dev
```

### CentOS/RHEL安装依赖

```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y pam-devel openssl-devel json-c-devel libcurl-devel
```

## 编译安装

### 1. 检查依赖

```bash
make check-deps
```

### 2. 编译所有组件

```bash
make all
```

### 3. 安装组件

```bash
sudo make install
```

### 4. 创建systemd服务

```bash
make install-service
sudo cp web3-auth-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable web3-auth-server
sudo systemctl start web3-auth-server
```

## 配置说明

### PAM配置

在PAM配置文件中添加以下行：

```
auth required pam_web3.so server_url=http://localhost:8080 timeout=30
```

### 服务器配置

认证服务器默认监听8080端口，可以通过修改源码中的`PORT`常量来更改。

### 客户端配置

客户端示例程序需要提供用户名和私钥：

```bash
./web3_client_example <username> <private_key_hex>
```

## 使用方法

### 1. 启动认证服务器

```bash
# 使用systemd服务
sudo systemctl start web3-auth-server

# 或直接运行
./web3_auth_server
```

### 2. 配置PAM

编辑PAM配置文件（如`/etc/pam.d/login`）：

```
# 添加Web3认证
auth required pam_web3.so server_url=http://localhost:8080 timeout=30
```

### 3. 测试客户端

```bash
# 使用示例客户端测试
./web3_client_example alice 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

### 4. 系统登录

用户可以通过以下方式登录：

1. 使用SSH登录
2. 使用本地终端登录
3. 使用图形界面登录

## API接口

### 获取挑战

**请求:**
```http
POST /api/challenge
Content-Type: application/json

{
    "username": "alice"
}
```

**响应:**
```json
{
    "challenge": "a1b2c3d4e5f6...",
    "nonce": "1234567890abcdef...",
    "timestamp": 1640995200,
    "message": "a1b2c3d4e5f6..."
}
```

### 验证签名

**请求:**
```http
POST /api/verify
Content-Type: application/json

{
    "address": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
    "signature": "0x1234567890abcdef...",
    "challenge": "a1b2c3d4e5f6..."
}
```

**响应:**
```json
{
    "success": true,
    "message": "Authentication successful",
    "username": "alice"
}
```

## 安全考虑

### 1. 私钥安全

- 私钥应该安全存储，不要硬编码在程序中
- 建议使用硬件钱包或安全的密钥管理系统
- 在生产环境中，私钥应该通过安全的方式传递给客户端

### 2. 网络安全

- 建议使用HTTPS进行通信
- 实施适当的防火墙规则
- 考虑使用VPN或专用网络

### 3. 挑战机制

- 挑战具有时效性（默认5分钟）
- 每个挑战只能使用一次
- 使用加密安全的随机数生成器

## 开发说明

### 项目结构

```
├── pam_web3.h              # PAM模块头文件
├── pam_web3.c              # PAM模块实现
├── web3_auth_server.c      # 认证服务器
├── web3_client_example.c   # 客户端示例
├── Makefile                # 构建配置
└── README.md               # 项目文档
```

### 编译选项

```bash
# 调试版本
make debug

# 发布版本
make release

# 清理构建文件
make clean
```

### 测试

```bash
# 测试编译
make test-compile

# 运行服务器
make run-server

# 测试客户端
make test-client
```

## 故障排除

### 常见问题

1. **编译错误**: 检查是否安装了所有依赖库
2. **PAM模块加载失败**: 检查模块路径和权限
3. **服务器连接失败**: 检查服务器是否运行和网络连接
4. **签名验证失败**: 检查私钥和签名格式

### 日志查看

```bash
# 查看PAM日志
sudo tail -f /var/log/auth.log

# 查看服务器日志
sudo journalctl -u web3-auth-server -f
```

## 贡献指南

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 推送到分支
5. 创建Pull Request

## 许可证

本项目采用MIT许可证。详见LICENSE文件。

## 联系方式

如有问题或建议，请通过以下方式联系：

- 创建Issue
- 发送邮件
- 提交Pull Request

## 更新日志

### v1.0.0
- 初始版本发布
- 支持基本的Web3钱包认证
- 提供PAM模块和认证服务器
- 包含客户端示例程序
