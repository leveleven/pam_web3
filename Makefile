# Web3 PAM Authentication System Makefile
# 编译器和标志
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -fPIC -O2
LDFLAGS = -shared
PAM_LDFLAGS = -lpam -lpam_misc
SERVER_LDFLAGS = -lpthread -ljson-c -lssl -lcrypto
CLIENT_LDFLAGS = -lcurl -ljson-c -lssl -lcrypto

# 目录
PAM_DIR = /lib/security
INSTALL_DIR = /usr/local/bin
CONFIG_DIR = /etc/pam.d

# 源文件
PAM_SOURCES = pam_web3.c
SERVER_SOURCES = web3_auth_server.c
CLIENT_SOURCES = web3_client_example.c

# 目标文件
PAM_TARGET = pam_web3.so
SERVER_TARGET = web3_auth_server
CLIENT_TARGET = web3_client_example

# 头文件
HEADERS = pam_web3.h

# 默认目标
all: $(PAM_TARGET) $(SERVER_TARGET) $(CLIENT_TARGET)

# 编译PAM模块
$(PAM_TARGET): $(PAM_SOURCES) $(HEADERS)
	@echo "Compiling PAM module..."
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(PAM_SOURCES) $(PAM_LDFLAGS) $(SERVER_LDFLAGS)
	@echo "PAM module compiled successfully"

# 编译服务器
$(SERVER_TARGET): $(SERVER_SOURCES)
	@echo "Compiling authentication server..."
	$(CC) $(CFLAGS) -o $@ $(SERVER_SOURCES) $(SERVER_LDFLAGS)
	@echo "Authentication server compiled successfully"

# 编译客户端示例
$(CLIENT_TARGET): $(CLIENT_SOURCES)
	@echo "Compiling client example..."
	$(CC) $(CFLAGS) -o $@ $(CLIENT_SOURCES) $(CLIENT_LDFLAGS)
	@echo "Client example compiled successfully"

# 安装PAM模块
install-pam: $(PAM_TARGET)
	@echo "Installing PAM module..."
	sudo cp $(PAM_TARGET) $(PAM_DIR)/
	sudo chmod 644 $(PAM_DIR)/$(PAM_TARGET)
	@echo "PAM module installed to $(PAM_DIR)/$(PAM_TARGET)"

# 安装服务器
install-server: $(SERVER_TARGET)
	@echo "Installing authentication server..."
	sudo cp $(SERVER_TARGET) $(INSTALL_DIR)/
	sudo chmod 755 $(INSTALL_DIR)/$(SERVER_TARGET)
	@echo "Authentication server installed to $(INSTALL_DIR)/$(SERVER_TARGET)"

# 安装客户端
install-client: $(CLIENT_TARGET)
	@echo "Installing client example..."
	sudo cp $(CLIENT_TARGET) $(INSTALL_DIR)/
	sudo chmod 755 $(INSTALL_DIR)/$(CLIENT_TARGET)
	@echo "Client example installed to $(INSTALL_DIR)/$(CLIENT_TARGET)"

# 安装所有组件
install: install-pam install-server install-client
	@echo "All components installed successfully"

# 创建PAM配置示例
install-config:
	@echo "Creating PAM configuration example..."
	@echo "# Web3 Authentication Configuration" > pam_web3_example
	@echo "# Add this line to your PAM configuration file:" >> pam_web3_example
	@echo "# auth required pam_web3.so server_url=http://localhost:8080 timeout=30" >> pam_web3_example
	@echo "PAM configuration example created: pam_web3_example"

# 创建systemd服务文件
install-service: $(SERVER_TARGET)
	@echo "Creating systemd service file..."
	@echo "[Unit]" > web3-auth-server.service
	@echo "Description=Web3 Authentication Server" >> web3-auth-server.service
	@echo "After=network.target" >> web3-auth-server.service
	@echo "" >> web3-auth-server.service
	@echo "[Service]" >> web3-auth-server.service
	@echo "Type=simple" >> web3-auth-server.service
	@echo "User=root" >> web3-auth-server.service
	@echo "ExecStart=$(INSTALL_DIR)/$(SERVER_TARGET)" >> web3-auth-server.service
	@echo "Restart=always" >> web3-auth-server.service
	@echo "RestartSec=5" >> web3-auth-server.service
	@echo "" >> web3-auth-server.service
	@echo "[Install]" >> web3-auth-server.service
	@echo "WantedBy=multi-user.target" >> web3-auth-server.service
	@echo "Systemd service file created: web3-auth-server.service"
	@echo "To install the service, run:"
	@echo "  sudo cp web3-auth-server.service /etc/systemd/system/"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable web3-auth-server"
	@echo "  sudo systemctl start web3-auth-server"

# 清理编译文件
clean:
	@echo "Cleaning build files..."
	rm -f $(PAM_TARGET) $(SERVER_TARGET) $(CLIENT_TARGET)
	rm -f *.o *.so
	rm -f pam_web3_example web3-auth-server.service
	@echo "Build files cleaned"

# 卸载
uninstall:
	@echo "Uninstalling components..."
	sudo rm -f $(PAM_DIR)/$(PAM_TARGET)
	sudo rm -f $(INSTALL_DIR)/$(SERVER_TARGET)
	sudo rm -f $(INSTALL_DIR)/$(CLIENT_TARGET)
	sudo rm -f /etc/systemd/system/web3-auth-server.service
	@echo "Components uninstalled"

# 测试编译
test-compile: $(PAM_TARGET) $(SERVER_TARGET) $(CLIENT_TARGET)
	@echo "Testing compilation..."
	@echo "All targets compiled successfully"

# 检查依赖
check-deps:
	@echo "Checking dependencies..."
	@which gcc > /dev/null || (echo "Error: gcc not found" && exit 1)
	@pkg-config --exists libssl || (echo "Error: OpenSSL development libraries not found" && exit 1)
	@pkg-config --exists json-c || (echo "Error: json-c development libraries not found" && exit 1)
	@pkg-config --exists libcurl || (echo "Error: libcurl development libraries not found" && exit 1)
	@echo "All dependencies found"

# 安装依赖（Ubuntu/Debian）
install-deps-ubuntu:
	@echo "Installing dependencies for Ubuntu/Debian..."
	sudo apt-get update
	sudo apt-get install -y build-essential libpam0g-dev libssl-dev libjson-c-dev libcurl4-openssl-dev
	@echo "Dependencies installed"

# 安装依赖（CentOS/RHEL）
install-deps-centos:
	@echo "Installing dependencies for CentOS/RHEL..."
	sudo yum groupinstall -y "Development Tools"
	sudo yum install -y pam-devel openssl-devel json-c-devel libcurl-devel
	@echo "Dependencies installed"

# 运行服务器（开发模式）
run-server: $(SERVER_TARGET)
	@echo "Starting authentication server in development mode..."
	./$(SERVER_TARGET)

# 运行客户端测试
test-client: $(CLIENT_TARGET)
	@echo "Testing client with example data..."
	@echo "Note: Make sure the server is running first"
	./$(CLIENT_TARGET) testuser 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

# 调试编译
debug: CFLAGS += -g -DDEBUG
debug: $(PAM_TARGET) $(SERVER_TARGET) $(CLIENT_TARGET)
	@echo "Debug versions compiled"

# 发布版本
release: CFLAGS += -DNDEBUG -O3
release: clean all
	@echo "Release versions compiled"

# 显示帮助
help:
	@echo "Web3 PAM Authentication System Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build all components (default)"
	@echo "  $(PAM_TARGET)     - Build PAM module only"
	@echo "  $(SERVER_TARGET)  - Build authentication server only"
	@echo "  $(CLIENT_TARGET)  - Build client example only"
	@echo ""
	@echo "Installation:"
	@echo "  install          - Install all components"
	@echo "  install-pam      - Install PAM module only"
	@echo "  install-server   - Install server only"
	@echo "  install-client   - Install client only"
	@echo "  install-config   - Create PAM configuration example"
	@echo "  install-service  - Create systemd service file"
	@echo ""
	@echo "Dependencies:"
	@echo "  check-deps       - Check if all dependencies are available"
	@echo "  install-deps-ubuntu - Install dependencies on Ubuntu/Debian"
	@echo "  install-deps-centos - Install dependencies on CentOS/RHEL"
	@echo ""
	@echo "Testing:"
	@echo "  test-compile     - Test compilation of all components"
	@echo "  run-server       - Run server in development mode"
	@echo "  test-client      - Test client with example data"
	@echo ""
	@echo "Build variants:"
	@echo "  debug            - Build debug versions"
	@echo "  release          - Build optimized release versions"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean            - Remove all build files"
	@echo "  uninstall        - Remove installed components"
	@echo "  help             - Show this help message"

# 声明伪目标
.PHONY: all install install-pam install-server install-client install-config install-service clean uninstall test-compile check-deps install-deps-ubuntu install-deps-centos run-server test-client debug release help
