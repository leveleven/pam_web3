#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define SERVER_URL "http://localhost:8080"
#define CHALLENGE_ENDPOINT "/api/challenge"
#define VERIFY_ENDPOINT "/api/verify"
#define BUFFER_SIZE 4096

// 结构体定义
typedef struct {
    char challenge[65];
    char nonce[33];
    long timestamp;
} challenge_response_t;

typedef struct {
    int success;
    char message[256];
    char username[64];
} verify_response_t;

// 全局变量
char response_buffer[BUFFER_SIZE] = {0};

// 函数声明
int request_challenge(const char *username, challenge_response_t *challenge);
int sign_message(const char *private_key_hex, const char *message, char *signature);
int send_verification(const char *address, const char *signature, const char *challenge, verify_response_t *response);
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
int build_ethereum_message_hash(const char *message, unsigned char *hash);
int keccak256_hash(const unsigned char *input, size_t input_len, unsigned char *output);
void print_usage(const char *program_name);

int main(int argc, char *argv[]) {
    char username[64] = {0};
    char private_key_hex[65] = {0};
    char wallet_address[43] = {0};
    challenge_response_t challenge;
    verify_response_t verify_response;
    char signature[131] = {0};
    int ret;
    
    // 解析命令行参数
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    
    strncpy(username, argv[1], sizeof(username) - 1);
    strncpy(private_key_hex, argv[2], sizeof(private_key_hex) - 1);
    
    // 从私钥计算钱包地址（简化实现）
    if (calculate_address_from_private_key(private_key_hex, wallet_address) != 0) {
        fprintf(stderr, "Error: Failed to calculate wallet address from private key\n");
        return 1;
    }
    
    printf("Web3 Authentication Client\n");
    printf("Username: %s\n", username);
    printf("Wallet Address: %s\n", wallet_address);
    printf("Server: %s\n\n", SERVER_URL);
    
    // 步骤1: 请求挑战
    printf("Step 1: Requesting challenge from server...\n");
    ret = request_challenge(username, &challenge);
    if (ret != 0) {
        fprintf(stderr, "Error: Failed to request challenge\n");
        return 1;
    }
    
    printf("Challenge received:\n");
    printf("  Challenge: %s\n", challenge.challenge);
    printf("  Nonce: %s\n", challenge.nonce);
    printf("  Timestamp: %ld\n\n", challenge.timestamp);
    
    // 步骤2: 签名消息
    printf("Step 2: Signing challenge message...\n");
    ret = sign_message(private_key_hex, challenge.challenge, signature);
    if (ret != 0) {
        fprintf(stderr, "Error: Failed to sign message\n");
        return 1;
    }
    
    printf("Signature generated: %s\n\n", signature);
    
    // 步骤3: 发送验证请求
    printf("Step 3: Sending verification to server...\n");
    ret = send_verification(wallet_address, signature, challenge.challenge, &verify_response);
    if (ret != 0) {
        fprintf(stderr, "Error: Failed to send verification\n");
        return 1;
    }
    
    // 步骤4: 显示结果
    printf("Verification result:\n");
    if (verify_response.success) {
        printf("  Status: SUCCESS\n");
        printf("  Message: %s\n", verify_response.message);
        printf("  Username: %s\n", verify_response.username);
        printf("\nAuthentication completed successfully!\n");
    } else {
        printf("  Status: FAILED\n");
        printf("  Message: %s\n", verify_response.message);
        printf("\nAuthentication failed!\n");
        return 1;
    }
    
    return 0;
}

// 请求挑战
int request_challenge(const char *username, challenge_response_t *challenge) {
    CURL *curl;
    CURLcode res;
    char url[512];
    char post_data[256];
    struct curl_slist *headers = NULL;
    json_object *json_obj, *challenge_obj, *nonce_obj, *timestamp_obj;
    
    curl = curl_easy_init();
    if (!curl) {
        return -1;
    }
    
    // 构建URL和POST数据
    snprintf(url, sizeof(url), "%s%s", SERVER_URL, CHALLENGE_ENDPOINT);
    snprintf(post_data, sizeof(post_data), "{\"username\":\"%s\"}", username);
    
    // 设置HTTP头
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    // 设置cURL选项
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    // 清空响应缓冲区
    memset(response_buffer, 0, BUFFER_SIZE);
    
    // 执行请求
    res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "cURL error: %s\n", curl_easy_strerror(res));
        return -1;
    }
    
    // 解析JSON响应
    json_obj = json_tokener_parse(response_buffer);
    if (!json_obj) {
        fprintf(stderr, "Failed to parse JSON response: %s\n", response_buffer);
        return -1;
    }
    
    if (json_object_object_get_ex(json_obj, "challenge", &challenge_obj) &&
        json_object_object_get_ex(json_obj, "nonce", &nonce_obj) &&
        json_object_object_get_ex(json_obj, "timestamp", &timestamp_obj)) {
        
        strncpy(challenge->challenge, json_object_get_string(challenge_obj), 64);
        challenge->challenge[64] = '\0';
        strncpy(challenge->nonce, json_object_get_string(nonce_obj), 32);
        challenge->nonce[32] = '\0';
        challenge->timestamp = json_object_get_int64(timestamp_obj);
        
        json_object_put(json_obj);
        return 0;
    }
    
    fprintf(stderr, "Invalid challenge response format\n");
    json_object_put(json_obj);
    return -1;
}

// 签名消息
int sign_message(const char *private_key_hex, const char *message, char *signature) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len;
    unsigned char hash[32];
    BIGNUM *priv_bn = NULL;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group;
    int ret = -1;
    
    // 构建以太坊消息哈希
    if (build_ethereum_message_hash(message, hash) != 0) {
        fprintf(stderr, "Failed to build ethereum message hash\n");
        goto cleanup;
    }
    
    // 从十六进制字符串创建私钥
    if (BN_hex2bn(&priv_bn, private_key_hex) == 0) {
        fprintf(stderr, "Failed to parse private key\n");
        goto cleanup;
    }
    
    // 创建EC密钥
    ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        fprintf(stderr, "Failed to create EC key\n");
        goto cleanup;
    }
    
    if (EC_KEY_set_private_key(ec_key, priv_bn) != 1) {
        fprintf(stderr, "Failed to set private key\n");
        goto cleanup;
    }
    
    // 计算公钥
    group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_key = EC_POINT_new(group);
    if (!pub_key) {
        fprintf(stderr, "Failed to create public key point\n");
        goto cleanup;
    }
    
    if (EC_POINT_mul(group, pub_key, priv_bn, NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to compute public key\n");
        EC_POINT_free(pub_key);
        goto cleanup;
    }
    
    if (EC_KEY_set_public_key(ec_key, pub_key) != 1) {
        fprintf(stderr, "Failed to set public key\n");
        EC_POINT_free(pub_key);
        goto cleanup;
    }
    
    EC_POINT_free(pub_key);
    
    // 创建EVP_PKEY
    pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        fprintf(stderr, "Failed to create EVP_PKEY\n");
        goto cleanup;
    }
    
    // 签名
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Failed to create MD context\n");
        goto cleanup;
    }
    
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        fprintf(stderr, "Failed to initialize signing\n");
        goto cleanup;
    }
    
    if (EVP_DigestSign(mdctx, NULL, &sig_len, hash, 32) != 1) {
        fprintf(stderr, "Failed to get signature length\n");
        goto cleanup;
    }
    
    sig = malloc(sig_len);
    if (!sig) {
        fprintf(stderr, "Failed to allocate signature buffer\n");
        goto cleanup;
    }
    
    if (EVP_DigestSign(mdctx, sig, &sig_len, hash, 32) != 1) {
        fprintf(stderr, "Failed to sign\n");
        goto cleanup;
    }
    
    // 转换为十六进制字符串
    signature[0] = '0';
    signature[1] = 'x';
    for (size_t i = 0; i < sig_len; i++) {
        sprintf(signature + 2 + i * 2, "%02x", sig[i]);
    }
    signature[2 + sig_len * 2] = '\0';
    
    ret = 0;
    
cleanup:
    if (sig) free(sig);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (ec_key) EC_KEY_free(ec_key);
    if (priv_bn) BN_free(priv_bn);
    
    return ret;
}

// 发送验证请求
int send_verification(const char *address, const char *signature, const char *challenge, verify_response_t *response) {
    CURL *curl;
    CURLcode res;
    char url[512];
    char post_data[512];
    struct curl_slist *headers = NULL;
    json_object *json_obj, *success_obj, *message_obj, *username_obj;
    
    curl = curl_easy_init();
    if (!curl) {
        return -1;
    }
    
    // 构建URL和POST数据
    snprintf(url, sizeof(url), "%s%s", SERVER_URL, VERIFY_ENDPOINT);
    snprintf(post_data, sizeof(post_data), 
             "{\"address\":\"%s\",\"signature\":\"%s\",\"challenge\":\"%s\"}",
             address, signature, challenge);
    
    // 设置HTTP头
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    // 设置cURL选项
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    // 清空响应缓冲区
    memset(response_buffer, 0, BUFFER_SIZE);
    
    // 执行请求
    res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "cURL error: %s\n", curl_easy_strerror(res));
        return -1;
    }
    
    // 解析JSON响应
    json_obj = json_tokener_parse(response_buffer);
    if (!json_obj) {
        fprintf(stderr, "Failed to parse JSON response: %s\n", response_buffer);
        return -1;
    }
    
    if (json_object_object_get_ex(json_obj, "success", &success_obj)) {
        response->success = json_object_get_boolean(success_obj);
        
        if (json_object_object_get_ex(json_obj, "message", &message_obj)) {
            strncpy(response->message, json_object_get_string(message_obj), 255);
            response->message[255] = '\0';
        }
        
        if (json_object_object_get_ex(json_obj, "username", &username_obj)) {
            strncpy(response->username, json_object_get_string(username_obj), 63);
            response->username[63] = '\0';
        }
        
        json_object_put(json_obj);
        return 0;
    }
    
    fprintf(stderr, "Invalid verification response format\n");
    json_object_put(json_obj);
    return -1;
}

// 从私钥计算地址（简化实现）
int calculate_address_from_private_key(const char *private_key_hex, char *address) {
    // 这里应该实现真正的地址计算
    // 实际应用中需要：
    // 1. 从私钥计算公钥
    // 2. 对公钥进行Keccak256哈希
    // 3. 取最后20字节作为地址
    
    // 简化实现：生成一个示例地址
    unsigned char hash[32];
    SHA256((unsigned char *)private_key_hex, strlen(private_key_hex), hash);
    
    snprintf(address, 43, "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
             hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
             hash[16], hash[17], hash[18], hash[19]);
    
    return 0;
}

// cURL写入回调函数
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char *buffer = (char *)userp;
    
    strncat(buffer, (char *)contents, realsize);
    return realsize;
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

// 打印使用说明
void print_usage(const char *program_name) {
    printf("Usage: %s <username> <private_key_hex>\n", program_name);
    printf("\n");
    printf("Arguments:\n");
    printf("  username        Username for authentication\n");
    printf("  private_key_hex Private key in hexadecimal format (without 0x prefix)\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s alice 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef\n", program_name);
    printf("\n");
    printf("Note: This is a demonstration client. In production, private keys should\n");
    printf("      be handled securely and never passed as command line arguments.\n");
}
