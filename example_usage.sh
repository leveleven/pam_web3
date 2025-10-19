#!/bin/bash

# Web3 PAM Authentication System - 使用示例脚本
# 此脚本演示如何设置和使用Web3 PAM认证系统

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Some operations may not work as expected."
    fi
}

# 检查依赖
check_dependencies() {
    print_info "Checking dependencies..."
    
    local missing_deps=()
    
    # 检查编译工具
    if ! command -v gcc &> /dev/null; then
        missing_deps+=("gcc")
    fi
    
    if ! command -v make &> /dev/null; then
        missing_deps+=("make")
    fi
    
    # 检查开发库
    if ! pkg-config --exists libssl; then
        missing_deps+=("libssl-dev")
    fi
    
    if ! pkg-config --exists json-c; then
        missing_deps+=("libjson-c-dev")
    fi
    
    if ! pkg-config --exists libcurl; then
        missing_deps+=("libcurl4-openssl-dev")
    fi
    
    if ! pkg-config --exists libpam; then
        missing_deps+=("libpam0g-dev")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_info "Please install missing dependencies:"
        print_info "Ubuntu/Debian: sudo apt-get install ${missing_deps[*]}"
        print_info "CentOS/RHEL: sudo yum install ${missing_deps[*]}"
        exit 1
    fi
    
    print_success "All dependencies are available"
}

# 编译项目
build_project() {
    print_info "Building project..."
    
    if make all; then
        print_success "Project built successfully"
    else
        print_error "Build failed"
        exit 1
    fi
}

# 启动认证服务器
start_server() {
    print_info "Starting authentication server..."
    
    # 检查服务器是否已经在运行
    if pgrep -f "web3_auth_server" > /dev/null; then
        print_warning "Authentication server is already running"
        return 0
    fi
    
    # 启动服务器
    ./web3_auth_server &
    local server_pid=$!
    
    # 等待服务器启动
    sleep 2
    
    if kill -0 $server_pid 2>/dev/null; then
        print_success "Authentication server started (PID: $server_pid)"
        echo $server_pid > server.pid
    else
        print_error "Failed to start authentication server"
        exit 1
    fi
}

# 停止认证服务器
stop_server() {
    print_info "Stopping authentication server..."
    
    if [ -f server.pid ]; then
        local server_pid=$(cat server.pid)
        if kill -0 $server_pid 2>/dev/null; then
            kill $server_pid
            print_success "Authentication server stopped"
        else
            print_warning "Authentication server was not running"
        fi
        rm -f server.pid
    else
        # 尝试通过进程名停止
        if pgrep -f "web3_auth_server" > /dev/null; then
            pkill -f "web3_auth_server"
            print_success "Authentication server stopped"
        else
            print_warning "Authentication server was not running"
        fi
    fi
}

# 测试客户端
test_client() {
    print_info "Testing client authentication..."
    
    # 测试用户名和私钥（仅用于演示）
    local test_username="testuser"
    local test_private_key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    
    print_info "Testing with username: $test_username"
    print_warning "Note: This is a demonstration with a test private key"
    
    if ./web3_client_example "$test_username" "$test_private_key"; then
        print_success "Client test completed successfully"
    else
        print_error "Client test failed"
        return 1
    fi
}

# 创建PAM配置示例
create_pam_config() {
    print_info "Creating PAM configuration example..."
    
    cat > pam_web3_example.conf << EOF
# Web3 PAM Authentication Configuration
# Add this line to your PAM configuration file (e.g., /etc/pam.d/login):

# For login authentication
auth required pam_web3.so server_url=http://localhost:8080 timeout=30

# For SSH authentication (add to /etc/pam.d/sshd)
auth required pam_web3.so server_url=http://localhost:8080 timeout=30

# For sudo authentication (add to /etc/pam.d/sudo)
auth required pam_web3.so server_url=http://localhost:8080 timeout=30

# Configuration options:
# server_url: URL of the authentication server
# timeout: Timeout in seconds for server communication
EOF
    
    print_success "PAM configuration example created: pam_web3_example.conf"
}

# 安装PAM模块
install_pam_module() {
    print_info "Installing PAM module..."
    
    if [ ! -f "pam_web3.so" ]; then
        print_error "PAM module not found. Please build the project first."
        return 1
    fi
    
    # 检查PAM目录
    local pam_dir="/lib/security"
    if [ ! -d "$pam_dir" ]; then
        pam_dir="/lib64/security"
        if [ ! -d "$pam_dir" ]; then
            print_error "PAM directory not found"
            return 1
        fi
    fi
    
    # 安装PAM模块
    if sudo cp pam_web3.so "$pam_dir/"; then
        sudo chmod 644 "$pam_dir/pam_web3.so"
        print_success "PAM module installed to $pam_dir/pam_web3.so"
    else
        print_error "Failed to install PAM module"
        return 1
    fi
}

# 显示使用说明
show_usage() {
    echo "Web3 PAM Authentication System - 使用示例脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  build         编译项目"
    echo "  start         启动认证服务器"
    echo "  stop          停止认证服务器"
    echo "  test          测试客户端"
    echo "  install       安装PAM模块"
    echo "  config        创建PAM配置示例"
    echo "  demo          运行完整演示"
    echo "  clean         清理构建文件"
    echo "  help          显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 demo       # 运行完整演示"
    echo "  $0 build      # 仅编译项目"
    echo "  $0 start      # 仅启动服务器"
}

# 运行完整演示
run_demo() {
    print_info "Running complete demonstration..."
    
    # 检查依赖
    check_dependencies
    
    # 编译项目
    build_project
    
    # 启动服务器
    start_server
    
    # 等待服务器完全启动
    sleep 3
    
    # 测试客户端
    test_client
    
    # 创建配置示例
    create_pam_config
    
    print_success "Demonstration completed successfully!"
    print_info "Next steps:"
    print_info "1. Review the PAM configuration example: pam_web3_example.conf"
    print_info "2. Install the PAM module: $0 install"
    print_info "3. Configure your PAM files according to the example"
    print_info "4. Test the authentication with a real Web3 wallet"
}

# 清理函数
cleanup() {
    print_info "Cleaning up..."
    stop_server
    make clean
    rm -f server.pid
    print_success "Cleanup completed"
}

# 主函数
main() {
    # 设置清理陷阱
    trap cleanup EXIT
    
    # 检查root权限
    check_root
    
    case "${1:-demo}" in
        "build")
            check_dependencies
            build_project
            ;;
        "start")
            start_server
            ;;
        "stop")
            stop_server
            ;;
        "test")
            test_client
            ;;
        "install")
            install_pam_module
            ;;
        "config")
            create_pam_config
            ;;
        "demo")
            run_demo
            ;;
        "clean")
            cleanup
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@"
