#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <json-c/json.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define MAX_CLIENTS 100
#define BUFFER_SIZE 4096
#define PORT 8080
#define CHALLENGE_TIMEOUT 300  // 5分钟超时

// 挑战信息结构
typedef struct {
    char username[64];
    char challenge[65];  // 32字节的十六进制字符串
    char nonce[33];
    time_t timestamp;
    int used;
} challenge_info_t;

// 全局挑战存储
challenge_info_t challenges[MAX_CLIENTS];
pthread_mutex_t challenges_mutex = PTHREAD_MUTEX_INITIALIZER;

// 函数声明
void *handle_client(void *arg);
int generate_challenge(char *challenge, char *nonce);
int verify_signature(const char *address, const char *signature, const char *message);
int recover_address_from_signature(const char *signature, const char *message, char *address);
int build_ethereum_message_hash(const char *message, unsigned char *hash);
int keccak256_hash(const unsigned char *input, size_t input_len, unsigned char *output);
void send_http_response(int client_socket, int status_code, const char *content_type, const char *body);
void send_json_response(int client_socket, int status_code, json_object *json_obj);
char *get_http_header_value(const char *headers, const char *name);
int parse_http_request(const char *request, char *method, char *path, char *body);

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    pthread_t thread_id;
    
    printf("Web3 Authentication Server starting on port %d...\n", PORT);
    
    // 创建socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    
    // 设置socket选项
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // 绑定地址
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }
    
    // 监听连接
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        exit(1);
    }
    
    printf("Server listening on port %d\n", PORT);
    
    // 初始化挑战存储
    memset(challenges, 0, sizeof(challenges));
    
    // 主循环：接受连接
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        printf("New connection from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // 创建线程处理客户端
        if (pthread_create(&thread_id, NULL, handle_client, &client_socket) != 0) {
            perror("Thread creation failed");
            close(client_socket);
        }
        
        pthread_detach(thread_id);
    }
    
    close(server_socket);
    return 0;
}

// 处理客户端请求
void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    char buffer[BUFFER_SIZE];
    char method[16], path[256], body[2048];
    json_object *json_obj, *response_obj;
    int bytes_read;
    
    // 读取HTTP请求
    bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0) {
        close(client_socket);
        return NULL;
    }
    
    buffer[bytes_read] = '\0';
    
    // 解析HTTP请求
    if (parse_http_request(buffer, method, path, body) != 0) {
        send_http_response(client_socket, 400, "text/plain", "Bad Request");
        close(client_socket);
        return NULL;
    }
    
    printf("Request: %s %s\n", method, path);
    
    // 处理不同的API端点
    if (strcmp(path, "/api/challenge") == 0 && strcmp(method, "POST") == 0) {
        // 处理挑战请求
        json_object *username_obj;
        char username[64];
        char challenge[65], nonce[33];
        int i;
        
        json_obj = json_tokener_parse(body);
        if (!json_obj || !json_object_object_get_ex(json_obj, "username", &username_obj)) {
            send_http_response(client_socket, 400, "application/json", 
                             "{\"error\":\"Invalid JSON or missing username\"}");
            close(client_socket);
            return NULL;
        }
        
        strncpy(username, json_object_get_string(username_obj), sizeof(username) - 1);
        username[sizeof(username) - 1] = '\0';
        
        // 生成挑战
        if (generate_challenge(challenge, nonce) != 0) {
            send_http_response(client_socket, 500, "application/json", 
                             "{\"error\":\"Failed to generate challenge\"}");
            json_object_put(json_obj);
            close(client_socket);
            return NULL;
        }
        
        // 存储挑战信息
        pthread_mutex_lock(&challenges_mutex);
        for (i = 0; i < MAX_CLIENTS; i++) {
            if (challenges[i].used == 0) {
                strncpy(challenges[i].username, username, sizeof(challenges[i].username) - 1);
                strncpy(challenges[i].challenge, challenge, sizeof(challenges[i].challenge) - 1);
                strncpy(challenges[i].nonce, nonce, sizeof(challenges[i].nonce) - 1);
                challenges[i].timestamp = time(NULL);
                challenges[i].used = 1;
                break;
            }
        }
        pthread_mutex_unlock(&challenges_mutex);
        
        if (i >= MAX_CLIENTS) {
            send_http_response(client_socket, 503, "application/json", 
                             "{\"error\":\"Server busy, try again later\"}");
            json_object_put(json_obj);
            close(client_socket);
            return NULL;
        }
        
        // 发送响应
        response_obj = json_object_new_object();
        json_object_object_add(response_obj, "challenge", json_object_new_string(challenge));
        json_object_object_add(response_obj, "nonce", json_object_new_string(nonce));
        json_object_object_add(response_obj, "timestamp", json_object_new_int64(time(NULL)));
        json_object_object_add(response_obj, "message", json_object_new_string(challenge));
        
        send_json_response(client_socket, 200, response_obj);
        json_object_put(response_obj);
        json_object_put(json_obj);
        
    } else if (strcmp(path, "/api/verify") == 0 && strcmp(method, "POST") == 0) {
        // 处理验证请求
        json_object *address_obj, *signature_obj, *challenge_obj;
        char address[43], signature[131], challenge[65];
        int i, found = 0;
        time_t current_time = time(NULL);
        
        json_obj = json_tokener_parse(body);
        if (!json_obj || 
            !json_object_object_get_ex(json_obj, "address", &address_obj) ||
            !json_object_object_get_ex(json_obj, "signature", &signature_obj) ||
            !json_object_object_get_ex(json_obj, "challenge", &challenge_obj)) {
            send_http_response(client_socket, 400, "application/json", 
                             "{\"error\":\"Invalid JSON or missing required fields\"}");
            close(client_socket);
            return NULL;
        }
        
        strncpy(address, json_object_get_string(address_obj), sizeof(address) - 1);
        strncpy(signature, json_object_get_string(signature_obj), sizeof(signature) - 1);
        strncpy(challenge, json_object_get_string(challenge_obj), sizeof(challenge) - 1);
        
        // 查找对应的挑战
        pthread_mutex_lock(&challenges_mutex);
        for (i = 0; i < MAX_CLIENTS; i++) {
            if (challenges[i].used == 1 && 
                strcmp(challenges[i].challenge, challenge) == 0) {
                
                // 检查是否超时
                if (current_time - challenges[i].timestamp > CHALLENGE_TIMEOUT) {
                    challenges[i].used = 0;  // 标记为未使用
                    pthread_mutex_unlock(&challenges_mutex);
                    send_http_response(client_socket, 408, "application/json", 
                                     "{\"error\":\"Challenge expired\"}");
                    json_object_put(json_obj);
                    close(client_socket);
                    return NULL;
                }
                
                found = 1;
                challenges[i].used = 0;  // 标记为已使用
                break;
            }
        }
        pthread_mutex_unlock(&challenges_mutex);
        
        if (!found) {
            send_http_response(client_socket, 404, "application/json", 
                             "{\"error\":\"Challenge not found or already used\"}");
            json_object_put(json_obj);
            close(client_socket);
            return NULL;
        }
        
        // 验证签名
        if (verify_signature(address, signature, challenge) == 0) {
            response_obj = json_object_new_object();
            json_object_object_add(response_obj, "success", json_object_new_boolean(1));
            json_object_object_add(response_obj, "message", json_object_new_string("Authentication successful"));
            json_object_object_add(response_obj, "username", json_object_new_string(challenges[i].username));
            
            send_json_response(client_socket, 200, response_obj);
            json_object_put(response_obj);
        } else {
            response_obj = json_object_new_object();
            json_object_object_add(response_obj, "success", json_object_new_boolean(0));
            json_object_object_add(response_obj, "error", json_object_new_string("Signature verification failed"));
            
            send_json_response(client_socket, 401, response_obj);
            json_object_put(response_obj);
        }
        
        json_object_put(json_obj);
        
    } else {
        // 404 Not Found
        send_http_response(client_socket, 404, "application/json", 
                         "{\"error\":\"Endpoint not found\"}");
    }
    
    close(client_socket);
    return NULL;
}

// 生成挑战
int generate_challenge(char *challenge, char *nonce) {
    unsigned char random_bytes[32];
    int i;
    
    // 生成32字节随机数据
    if (RAND_bytes(random_bytes, 32) != 1) {
        return -1;
    }
    
    // 转换为十六进制字符串
    for (i = 0; i < 32; i++) {
        sprintf(challenge + i * 2, "%02x", random_bytes[i]);
    }
    challenge[64] = '\0';
    
    // 生成nonce
    for (i = 0; i < 16; i++) {
        sprintf(nonce + i * 2, "%02x", random_bytes[i]);
    }
    nonce[32] = '\0';
    
    return 0;
}

// 验证签名
int verify_signature(const char *address, const char *signature, const char *message) {
    char recovered_address[43];
    
    if (recover_address_from_signature(signature, message, recovered_address) != 0) {
        return -1;
    }
    
    // 比较地址（不区分大小写）
    if (strcasecmp(address, recovered_address) != 0) {
        return -1;
    }
    
    return 0;
}

// 从签名恢复地址（简化实现）
int recover_address_from_signature(const char *signature, const char *message, char *address) {
    unsigned char hash[32];
    
    // 构建以太坊消息哈希
    if (build_ethereum_message_hash(message, hash) != 0) {
        return -1;
    }
    
    // 这里应该实现真正的ECDSA签名恢复
    // 为了演示，我们使用简化的实现
    // 实际应用中应该使用libsecp256k1库
    
    // 简化实现：假设签名验证通过，返回一个示例地址
    snprintf(address, 43, "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
             hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
             hash[16], hash[17], hash[18], hash[19]);
    
    return 0;
}

// 构建以太坊消息哈希
int build_ethereum_message_hash(const char *message, unsigned char *hash) {
    char prefixed_message[1024];
    unsigned char message_hash[32];
    
    // 添加以太坊消息前缀
    snprintf(prefixed_message, sizeof(prefixed_message), 
             "\x19Ethereum Signed Message:\n%zu%s", strlen(message), message);
    
    // 计算Keccak256哈希（这里用SHA256代替）
    if (keccak256_hash((unsigned char *)prefixed_message, strlen(prefixed_message), message_hash) != 0) {
        return -1;
    }
    
    memcpy(hash, message_hash, 32);
    return 0;
}

// Keccak256哈希实现（简化版本）
int keccak256_hash(const unsigned char *input, size_t input_len, unsigned char *output) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;
    
    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, input_len);
    EVP_DigestFinal_ex(mdctx, output, &md_len);
    EVP_MD_CTX_free(mdctx);
    
    return 0;
}

// 发送HTTP响应
void send_http_response(int client_socket, int status_code, const char *content_type, const char *body) {
    char response[BUFFER_SIZE];
    const char *status_text;
    
    switch (status_code) {
        case 200: status_text = "OK"; break;
        case 400: status_text = "Bad Request"; break;
        case 401: status_text = "Unauthorized"; break;
        case 404: status_text = "Not Found"; break;
        case 408: status_text = "Request Timeout"; break;
        case 500: status_text = "Internal Server Error"; break;
        case 503: status_text = "Service Unavailable"; break;
        default: status_text = "Unknown"; break;
    }
    
    snprintf(response, sizeof(response),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %zu\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
             "Access-Control-Allow-Headers: Content-Type\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             status_code, status_text, content_type, strlen(body), body);
    
    write(client_socket, response, strlen(response));
}

// 发送JSON响应
void send_json_response(int client_socket, int status_code, json_object *json_obj) {
    const char *json_string = json_object_to_json_string(json_obj);
    send_http_response(client_socket, status_code, "application/json", json_string);
}

// 获取HTTP头值
char *get_http_header_value(const char *headers, const char *name) {
    char search_pattern[256];
    char *found, *value_start, *value_end;
    
    snprintf(search_pattern, sizeof(search_pattern), "%s:", name);
    found = strstr(headers, search_pattern);
    if (!found) {
        return NULL;
    }
    
    value_start = found + strlen(search_pattern);
    while (*value_start == ' ') value_start++;
    
    value_end = strchr(value_start, '\r');
    if (!value_end) {
        value_end = strchr(value_start, '\n');
    }
    if (!value_end) {
        return NULL;
    }
    
    size_t value_len = value_end - value_start;
    char *value = malloc(value_len + 1);
    if (value) {
        strncpy(value, value_start, value_len);
        value[value_len] = '\0';
    }
    
    return value;
}

// 解析HTTP请求
int parse_http_request(const char *request, char *method, char *path, char *body) {
    char *line_end, *body_start;
    
    // 解析请求行
    line_end = strchr(request, '\n');
    if (!line_end) {
        return -1;
    }
    
    if (sscanf(request, "%15s %255s", method, path) != 2) {
        return -1;
    }
    
    // 查找请求体
    body_start = strstr(request, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        strncpy(body, body_start, 2047);
        body[2047] = '\0';
    } else {
        body[0] = '\0';
    }
    
    return 0;
}
