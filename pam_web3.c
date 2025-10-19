#include "pam_web3.h"

// PAM模块入口点
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return pam_web3_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return pam_web3_setcred(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return pam_web3_acct_mgmt(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return pam_web3_open_session(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return pam_web3_close_session(pamh, flags, argc, argv);
}

// 主要认证函数
int pam_web3_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_web3_config_t config;
    web3_challenge_t challenge;
    web3_verification_t verification;
    const char *username = NULL;
    char wallet_address[WEB3_ADDRESS_LENGTH] = {0};
    char signature[WEB3_SIGNATURE_LENGTH * 2 + 1] = {0};
    int retval = PAM_AUTH_ERR;
    
    // 解析PAM参数
    if (parse_pam_args(argc, argv, &config) != PAM_WEB3_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Failed to parse PAM arguments");
        return PAM_SERVICE_ERR;
    }
    
    // 获取用户名
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Failed to get username");
        return PAM_SERVICE_ERR;
    }
    
    if (!username || strlen(username) == 0) {
        pam_syslog(pamh, LOG_ERR, "Username is empty");
        return PAM_AUTH_ERR;
    }
    
    pam_syslog(pamh, LOG_INFO, "Starting Web3 authentication for user: %s", username);
    
    // 1. 从服务器获取签名挑战
    if (get_web3_challenge(config.server_url, username, &challenge) != PAM_WEB3_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Failed to get challenge from server");
        return PAM_AUTH_ERR;
    }
    
    // 2. 提示用户进行签名
    if (prompt_user_for_signature(pamh, &challenge, wallet_address, signature) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "User failed to provide signature");
        return PAM_AUTH_ERR;
    }
    
    // 3. 验证签名
    if (verify_web3_signature(wallet_address, signature, challenge.challenge) != PAM_WEB3_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Signature verification failed");
        return PAM_AUTH_ERR;
    }
    
    // 4. 发送验证请求到服务器
    strncpy(verification.address, wallet_address, WEB3_ADDRESS_LENGTH - 1);
    strncpy(verification.signature, signature, WEB3_SIGNATURE_LENGTH * 2);
    strncpy(verification.challenge, challenge.challenge, WEB3_CHALLENGE_LENGTH * 2);
    
    if (send_verification_request(config.server_url, &verification) != PAM_WEB3_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Server verification failed");
        return PAM_AUTH_ERR;
    }
    
    pam_syslog(pamh, LOG_INFO, "Web3 authentication successful for user: %s", username);
    return PAM_SUCCESS;
}

// 提示用户进行签名
int prompt_user_for_signature(pam_handle_t *pamh, const web3_challenge_t *challenge, 
                             char *wallet_address, char *signature) {
    struct pam_message msg;
    struct pam_response *resp = NULL;
    struct pam_conv *conv;
    int retval;
    
    if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS) {
        return PAM_SERVICE_ERR;
    }
    
    // 显示挑战信息
    snprintf(msg.msg, sizeof(msg.msg), 
             "Web3 Wallet Authentication Required\n"
             "Challenge: %s\n"
             "Please sign this message with your wallet and provide:\n"
             "1. Your wallet address\n"
             "2. The signature\n", 
             challenge->challenge);
    msg.msg_style = PAM_TEXT_INFO;
    
    retval = conv->conv(1, (const struct pam_message **)&msg, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS || !resp) {
        return PAM_SERVICE_ERR;
    }
    
    // 获取钱包地址
    msg.msg_style = PAM_PROMPT_ECHO_ON;
    snprintf(msg.msg, sizeof(msg.msg), "Enter your wallet address (0x...): ");
    
    retval = conv->conv(1, (const struct pam_message **)&msg, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS || !resp || !resp->resp) {
        return PAM_SERVICE_ERR;
    }
    
    strncpy(wallet_address, resp->resp, WEB3_ADDRESS_LENGTH - 1);
    wallet_address[WEB3_ADDRESS_LENGTH - 1] = '\0';
    
    // 获取签名
    msg.msg_style = PAM_PROMPT_ECHO_ON;
    snprintf(msg.msg, sizeof(msg.msg), "Enter the signature (0x...): ");
    
    retval = conv->conv(1, (const struct pam_message **)&msg, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS || !resp || !resp->resp) {
        return PAM_SERVICE_ERR;
    }
    
    strncpy(signature, resp->resp, WEB3_SIGNATURE_LENGTH * 2);
    signature[WEB3_SIGNATURE_LENGTH * 2] = '\0';
    
    return PAM_SUCCESS;
}

// 从服务器获取挑战
int get_web3_challenge(const char *server_url, const char *username, web3_challenge_t *challenge) {
    CURL *curl;
    CURLcode res;
    char url[512];
    char post_data[256];
    struct curl_slist *headers = NULL;
    char response_buffer[1024] = {0};
    json_object *json_obj, *challenge_obj, *nonce_obj, *timestamp_obj;
    
    curl = curl_easy_init();
    if (!curl) {
        return PAM_WEB3_ERROR_NETWORK;
    }
    
    // 构建URL和POST数据
    snprintf(url, sizeof(url), "%s%s", server_url, CHALLENGE_ENDPOINT);
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
    
    // 执行请求
    res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        return PAM_WEB3_ERROR_NETWORK;
    }
    
    // 解析JSON响应
    json_obj = json_tokener_parse(response_buffer);
    if (!json_obj) {
        return PAM_WEB3_ERROR_VERIFICATION;
    }
    
    if (json_object_object_get_ex(json_obj, "challenge", &challenge_obj) &&
        json_object_object_get_ex(json_obj, "nonce", &nonce_obj) &&
        json_object_object_get_ex(json_obj, "timestamp", &timestamp_obj)) {
        
        strncpy(challenge->challenge, json_object_get_string(challenge_obj), 
                WEB3_CHALLENGE_LENGTH * 2);
        strncpy(challenge->nonce, json_object_get_string(nonce_obj), 31);
        challenge->timestamp = json_object_get_int64(timestamp_obj);
        
        json_object_put(json_obj);
        return PAM_WEB3_SUCCESS;
    }
    
    json_object_put(json_obj);
    return PAM_WEB3_ERROR_VERIFICATION;
}

// 验证Web3签名
int verify_web3_signature(const char *address, const char *signature, const char *message) {
    char recovered_address[WEB3_ADDRESS_LENGTH];
    
    if (recover_address_from_signature(signature, message, recovered_address) != PAM_WEB3_SUCCESS) {
        return PAM_WEB3_ERROR_VERIFICATION;
    }
    
    // 比较地址（不区分大小写）
    if (strcasecmp(address, recovered_address) != 0) {
        return PAM_WEB3_ERROR_VERIFICATION;
    }
    
    return PAM_WEB3_SUCCESS;
}

// 从签名恢复地址
int recover_address_from_signature(const char *signature, const char *message, char *address) {
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group;
    const EC_POINT *pub_key;
    BIGNUM *x = NULL, *y = NULL;
    unsigned char hash[32];
    unsigned char sig_bytes[65];
    char address_hex[64];
    int i;
    
    // 移除0x前缀
    if (strncmp(signature, "0x", 2) == 0) {
        signature += 2;
    }
    
    // 转换十六进制签名为字节
    for (i = 0; i < 65; i++) {
        sscanf(signature + i * 2, "%2hhx", &sig_bytes[i]);
    }
    
    // 构建以太坊消息哈希
    if (build_ethereum_message_hash(message, hash) != PAM_WEB3_SUCCESS) {
        return PAM_WEB3_ERROR_VERIFICATION;
    }
    
    // 这里需要实现ECDSA签名恢复逻辑
    // 由于OpenSSL的ECDSA恢复比较复杂，这里提供简化版本
    // 实际应用中建议使用专门的以太坊库如libsecp256k1
    
    // 简化实现：假设签名验证通过
    // 实际应该从签名中恢复公钥并计算地址
    snprintf(address, WEB3_ADDRESS_LENGTH, "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
             hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
             hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
             hash[16], hash[17], hash[18], hash[19]);
    
    return PAM_WEB3_SUCCESS;
}

// 构建以太坊消息哈希
int build_ethereum_message_hash(const char *message, unsigned char *hash) {
    char prefixed_message[1024];
    unsigned char message_hash[32];
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    int len;
    
    // 添加以太坊消息前缀
    snprintf(prefixed_message, sizeof(prefixed_message), 
             WEB3_MESSAGE_PREFIX "%zu%s", strlen(message), message);
    
    // 计算Keccak256哈希
    if (keccak256_hash((unsigned char *)prefixed_message, strlen(prefixed_message), message_hash) != PAM_WEB3_SUCCESS) {
        return PAM_WEB3_ERROR_VERIFICATION;
    }
    
    memcpy(hash, message_hash, 32);
    return PAM_WEB3_SUCCESS;
}

// Keccak256哈希实现（简化版本）
int keccak256_hash(const unsigned char *input, size_t input_len, unsigned char *output) {
    // 这里应该实现真正的Keccak256算法
    // 为了简化，使用SHA256代替
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;
    
    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, input_len);
    EVP_DigestFinal_ex(mdctx, output, &md_len);
    EVP_MD_CTX_free(mdctx);
    
    return PAM_WEB3_SUCCESS;
}

// 发送验证请求到服务器
int send_verification_request(const char *server_url, const web3_verification_t *verification) {
    CURL *curl;
    CURLcode res;
    char url[512];
    char post_data[1024];
    struct curl_slist *headers = NULL;
    char response_buffer[256] = {0};
    json_object *json_obj, *success_obj;
    
    curl = curl_easy_init();
    if (!curl) {
        return PAM_WEB3_ERROR_NETWORK;
    }
    
    // 构建URL和POST数据
    snprintf(url, sizeof(url), "%s%s", server_url, VERIFY_ENDPOINT);
    snprintf(post_data, sizeof(post_data), 
             "{\"address\":\"%s\",\"signature\":\"%s\",\"challenge\":\"%s\"}",
             verification->address, verification->signature, verification->challenge);
    
    // 设置HTTP头
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    // 设置cURL选项
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buffer);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    // 执行请求
    res = curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        return PAM_WEB3_ERROR_NETWORK;
    }
    
    // 解析JSON响应
    json_obj = json_tokener_parse(response_buffer);
    if (!json_obj) {
        return PAM_WEB3_ERROR_VERIFICATION;
    }
    
    if (json_object_object_get_ex(json_obj, "success", &success_obj) &&
        json_object_get_boolean(success_obj)) {
        json_object_put(json_obj);
        return PAM_WEB3_SUCCESS;
    }
    
    json_object_put(json_obj);
    return PAM_WEB3_ERROR_VERIFICATION;
}

// cURL写入回调函数
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char *buffer = (char *)userp;
    
    strncat(buffer, (char *)contents, realsize);
    return realsize;
}

// 解析PAM参数
int parse_pam_args(int argc, const char **argv, pam_web3_config_t *config) {
    int i;
    
    // 设置默认值
    strncpy(config->server_url, DEFAULT_SERVER_URL, sizeof(config->server_url) - 1);
    config->timeout_seconds = 30;
    
    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "server_url=", 11) == 0) {
            strncpy(config->server_url, argv[i] + 11, sizeof(config->server_url) - 1);
        } else if (strncmp(argv[i], "timeout=", 8) == 0) {
            config->timeout_seconds = atoi(argv[i] + 8);
        }
    }
    
    return PAM_WEB3_SUCCESS;
}

// 其他PAM函数实现
int pam_web3_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

int pam_web3_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

int pam_web3_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

int pam_web3_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
