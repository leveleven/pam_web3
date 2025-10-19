#ifndef PAM_WEB3_H
#define PAM_WEB3_H

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <curl/curl.h>
#include <json-c/json.h>

// Web3签名验证相关常量
#define WEB3_CHALLENGE_LENGTH 32
#define WEB3_SIGNATURE_LENGTH 65
#define WEB3_ADDRESS_LENGTH 42
#define WEB3_MESSAGE_PREFIX "\x19Ethereum Signed Message:\n"

// 服务器配置
#define DEFAULT_SERVER_URL "http://localhost:8080"
#define CHALLENGE_ENDPOINT "/api/challenge"
#define VERIFY_ENDPOINT "/api/verify"

// 错误代码
#define PAM_WEB3_SUCCESS 0
#define PAM_WEB3_ERROR_INVALID_PARAMS -1
#define PAM_WEB3_ERROR_NETWORK -2
#define PAM_WEB3_ERROR_VERIFICATION -3
#define PAM_WEB3_ERROR_TIMEOUT -4

// 结构体定义
typedef struct {
    char server_url[256];
    int timeout_seconds;
    char challenge_message[512];
    char wallet_address[WEB3_ADDRESS_LENGTH];
    char signature[WEB3_SIGNATURE_LENGTH * 2 + 1];
} pam_web3_config_t;

typedef struct {
    char challenge[WEB3_CHALLENGE_LENGTH * 2 + 1];
    char nonce[32];
    time_t timestamp;
} web3_challenge_t;

typedef struct {
    char address[WEB3_ADDRESS_LENGTH];
    char signature[WEB3_SIGNATURE_LENGTH * 2 + 1];
    char challenge[WEB3_CHALLENGE_LENGTH * 2 + 1];
} web3_verification_t;

// 函数声明
int pam_web3_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_web3_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_web3_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_web3_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv);
int pam_web3_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv);

// 内部函数
int get_web3_challenge(const char *server_url, const char *username, web3_challenge_t *challenge);
int verify_web3_signature(const char *address, const char *signature, const char *message);
int send_verification_request(const char *server_url, const web3_verification_t *verification);
int parse_pam_args(int argc, const char **argv, pam_web3_config_t *config);
void generate_random_challenge(char *challenge, size_t length);
int recover_address_from_signature(const char *signature, const char *message, char *address);
int keccak256_hash(const unsigned char *input, size_t input_len, unsigned char *output);

#endif // PAM_WEB3_H
