#include <iostream>
#include <vector>
#include <cstring>
#include <random>

// 示例：定义椭圆曲线参数（以SM2推荐曲线为例）
struct ECPoint {
    uint64_t x;
    uint64_t y;
};

struct SM2Key {
    uint64_t private_key;
    ECPoint public_key;
};

// 椭圆曲线参数（简化版）
const uint64_t P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF; // 素数P
const uint64_t A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC; // 参数A
const uint64_t B = 0x28E9FA9E9D9F5E344D5AEF6B7FC7C297FDFC7E7E7E7E7E7E7E7E7E7E7E7E7E7E; // 参数B
const ECPoint G = {0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7, 
                   0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0}; // 基点G
const uint64_t N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123; // 阶N

// 椭圆曲线加法（简化版）
ECPoint ec_add(const ECPoint &p1, const ECPoint &p2) {
    if (p1.x == 0 && p1.y == 0) return p2; // P1是无穷远点
    if (p2.x == 0 && p2.y == 0) return p1; // P2是无穷远点

    uint64_t lambda;
    if (p1.x == p2.x && p1.y == p2.y) {
        // 计算斜率 λ = (3 * x1^2 + a) / (2 * y1) mod p
        lambda = (3 * p1.x * p1.x + A) / (2 * p1.y);
    } else {
        // 计算斜率 λ = (y2 - y1) / (x2 - x1) mod p
        lambda = (p2.y - p1.y) / (p2.x - p1.x);
    }

    uint64_t x3 = (lambda * lambda - p1.x - p2.x) % P;
    uint64_t y3 = (lambda * (p1.x - x3) - p1.y) % P;

    return {x3, y3};
}

// 椭圆曲线标量乘法（简化版）
ECPoint ec_mul(uint64_t k, const ECPoint &p) {
    ECPoint result = {0, 0}; // 无穷远点
    ECPoint temp = p;

    while (k > 0) {
        if (k & 1) {
            result = ec_add(result, temp);
        }
        temp = ec_add(temp, temp);
        k >>= 1;
    }

    return result;
}

// 密钥生成
bool sm2_key_generate(SM2Key &key) {
    // 生成私钥（随机数）
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, N - 1);
    key.private_key = dis(gen);

    // 生成公钥（私钥 * 基点）
    key.public_key = ec_mul(key.private_key, G);
    return true;
}

// 加密
bool sm2_encrypt(const SM2Key &key, const uint8_t *plaintext, size_t plaintext_len,
                 uint8_t *ciphertext, size_t &ciphertext_len) {
    // 简化版：仅展示加密流程框架
    if (plaintext_len == 0) return false;

    // 生成随机数k
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, N - 1);
    uint64_t k = dis(gen);

    // 计算椭圆曲线点C1 = k * G
    ECPoint C1 = ec_mul(k, G);

    // 计算共享密钥 k * PublicKey
    ECPoint shared_key = ec_mul(k, key.public_key);

    // 简化：将共享密钥的x坐标作为加密密钥
    uint64_t encryption_key = shared_key.x;

    // 加密数据
    for (size_t i = 0; i < plaintext_len; ++i) {
        ciphertext[i] = plaintext[i] ^ (encryption_key & 0xFF);
        encryption_key >>= 8;
    }

    ciphertext_len = plaintext_len;
    return true;
}

// 解密
bool sm2_decrypt(const SM2Key &key, const uint8_t *ciphertext, size_t ciphertext_len,
                 uint8_t *plaintext, size_t &plaintext_len) {
    if (ciphertext_len == 0) return false;

    // 计算共享密钥 PrivateKey * C1
    ECPoint shared_key = ec_mul(key.private_key, {1, 2}); // 假设C1已知

    // 简化：将共享密钥的x坐标作为解密密钥
    uint64_t decryption_key = shared_key.x;

    // 解密数据
    for (size_t i = 0; i < ciphertext_len; ++i) {
        plaintext[i] = ciphertext[i] ^ (decryption_key & 0xFF);
        decryption_key >>= 8;
    }

    plaintext_len = ciphertext_len;
    return true;
}

void printHex(const std::string &label, const std::vector<uint8_t> &data) {
    std::cout << label << ": ";
    for (uint8_t byte : data) {
        printf("%02X", byte);
    }
    std::cout << std::endl;
}

int main() {
    SM2Key key;
    uint8_t plaintext[] = "Hello, SM2!";
    uint8_t ciphertext[256];
    size_t ciphertext_len;
    uint8_t decrypted[256];
    size_t decrypted_len;

    // 生成密钥对
    if (!sm2_key_generate(key)) {
        std::cerr << "密钥生成失败！" << std::endl;
        return -1;
    }

    // 打印私钥和公钥
    std::cout << "私钥: " << key.private_key << std::endl;
    std::cout << "公钥: (" << key.public_key.x << ", " << key.public_key.y << ")" << std::endl;

    // 加密
    if (!sm2_encrypt(key, plaintext, sizeof(plaintext) - 1, ciphertext, ciphertext_len)) {
        std::cerr << "加密失败！" << std::endl;
        return -1;
    }

    std::cout << "加密成功！" << std::endl;

    // 解密
    if (!sm2_decrypt(key, ciphertext, ciphertext_len, decrypted, decrypted_len)) {
        std::cerr << "解密失败！" << std::endl;
        return -1;
    }

    std::cout << "解密成功！" << std::endl;
    std::cout << "解密结果: " << std::string(decrypted, decrypted + decrypted_len) << std::endl;

    return 0;
}
