#include <openssl/sm9.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    // 初始化 OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 生成SM9主密钥对
    SM9_MASTER_KEY *master = SM9_MASTER_KEY_new();
    if (!master) handle_openssl_error();

    if (!SM9_generate_master_key(master, NID_sm9sign)) {
        std::cerr << "SM9主密钥生成失败" << std::endl;
        handle_openssl_error();
    }

    // 导出主公钥
    unsigned char pubkey[512];
    int pubkey_len = i2d_SM9PublicKey(master->public_key, nullptr);
    if (pubkey_len <= 0) handle_openssl_error();

    unsigned char *p = pubkey;
    i2d_SM9PublicKey(master->public_key, &p);

    // 用户标识
    const char *id = "user@example.com";
    size_t idlen = strlen(id);

    // 生成用户私钥
    SM9PrivateKey *user_sk = SM9PrivateKey_new();
    if (!SM9_extract_private_key(master, user_sk, (const unsigned char*)id, idlen)) {
        std::cerr << "SM9用户私钥生成失败" << std::endl;
        handle_openssl_error();
    }

    // 签名
    const char *msg = "Hello SM9!";
    unsigned char sig[256];
    size_t siglen = sizeof(sig);

    if (!SM9_sign(master, (const unsigned char*)msg, strlen(msg), sig, &siglen, (const unsigned char*)id, idlen)) {
        std::cerr << "SM9签名失败" << std::endl;
        handle_openssl_error();
    }

    std::cout << "签名成功，长度: " << siglen << std::endl;

    // 验证签名
    int verify = SM9_verify(master->public_key, (const unsigned char*)msg, strlen(msg), sig, siglen, (const unsigned char*)id, idlen);
    if (verify == 1) {
        std::cout << "签名验证成功" << std::endl;
    } else {
        std::cout << "签名验证失败" << std::endl;
    }

    // 释放资源
    SM9_MASTER_KEY_free(master);
    SM9PrivateKey_free(user_sk);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}