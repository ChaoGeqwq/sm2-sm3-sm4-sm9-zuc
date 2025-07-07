#include <iostream>
#include <vector>
#include <cmath>
#include <numeric>
#include <tuple> // 添加缺失的头文件
#include <random>

// 使用大整数库或自定义结构来处理256位值
struct uint256_t {
    uint64_t parts[4]; // 分为4个64位部分
};

// 椭圆曲线参数 (secp256k1) - 简化版，实际需要完整实现
const uint64_t P = 0xFFFFFEFFFFFC2F; // 简化后的素数域
const uint64_t A = 0;
const uint64_t B = 7;
const uint64_t Gx = 0x79BE667EF9DCBB; // 简化后的基点坐标
const uint64_t Gy = 0x483ADA7726A3C4; // 简化后的基点坐标
const uint64_t N = 0xFFFFFEBAAEDCE6;  // 简化后的基点阶数

// 椭圆曲线点结构
struct Point {
    uint64_t x;
    uint64_t y;
    bool infinity; // 是否为无穷远点
    
    Point() : x(0), y(0), infinity(true) {}
    Point(uint64_t x, uint64_t y) : x(x), y(y), infinity(false) {}
};

// 模运算 (a mod p)
uint64_t mod(uint64_t a, uint64_t p) {
    a %= p;
    return a < 0 ? a + p : a;
}

// 模逆元 (扩展欧几里得算法)
uint64_t inv(uint64_t a, uint64_t p) {
    int64_t t = 0, newt = 1;
    int64_t r = p, newr = a;
    
    while (newr != 0) {
        uint64_t quotient = r / newr;
        std::tie(t, newt) = std::make_tuple(newt, t - quotient * newt);
        std::tie(r, newr) = std::make_tuple(newr, r - quotient * newr);
    }
    
    if (r > 1) throw std::runtime_error("a is not invertible");
    if (t < 0) t += p;
    
    return mod(t, p);
}

// 椭圆曲线点加法
Point point_add(const Point& P, const Point& Q, uint64_t p) { // 添加p参数
    if (P.infinity) return Q;
    if (Q.infinity) return P;
    if (P.x == Q.x && P.y != Q.y) return Point(); // 返回无穷远点
    
    uint64_t lambda;
    if (P.x == Q.x && P.y == Q.y) {
        // 点加倍
        lambda = mod(mod(3 * P.x * P.x, p) * inv(2 * P.y, p), p);
    } else {
        // 点相加
        lambda = mod(Q.y - P.y, p) * inv(mod(Q.x - P.x, p), p);
    }
    
    uint64_t x3 = mod(lambda * lambda - P.x - Q.x, p);
    uint64_t y3 = mod(lambda * (P.x - x3) - P.y, p);
    
    return Point(x3, y3);
}

// 椭圆曲线点乘法 (倍加算法)
Point point_multiply(const Point& P, uint64_t k, uint64_t p) {
    Point result = P;  // 显式初始化
    Point addend = P;
    
    while (k) {
        if (k & 1) {
            result = point_add(result, addend, p);
        }
        addend = point_add(addend, addend, p);
        k >>= 1;
    }
    
    return result;
}

// 简化版ECC加密
std::vector<uint64_t> ecc_encrypt(const Point& pub_key, uint64_t message, uint64_t p) {
    // 1. 生成随机数 k
    std::random_device rd;
    std::mt19937_64 gen(rd()); 
    std::uniform_int_distribution<uint64_t> dist(1, p - 1); // 1 ≤ k < p
    uint64_t k = dist(gen);

    // 2. 计算 C1 = kG
    Point C1 = point_multiply(Point(Gx, Gy), k, p);
    
    // 3. 计算共享秘密 S = k * PubKey
    Point S = point_multiply(pub_key, k, p);
    
    // 4. 加密消息
    uint64_t C2 = mod(message + S.x, p);
    
    return {C1.x, C1.y, C2};
}



// 简化版ECC解密
uint64_t ecc_decrypt(uint64_t private_key, const std::vector<uint64_t>& ciphertext, uint64_t p) {
    // 1. 提取密文组件
    Point C1(ciphertext[0], ciphertext[1]);
    uint64_t C2 = ciphertext[2];
    
    // 2. 计算共享秘密
    Point S = point_multiply(C1, private_key, p);
    
    // 3. 解密消息
    // return mod(C2 - S.x, p);
    return mod(C2 + p - S.x, p);

}

int main() {
    // 使用简化后的参数
    uint64_t curve_p = P;
    
    // 1. 生成密钥对
    uint64_t private_key = 1234567890; 
    Point public_key = point_multiply(Point(Gx, Gy), private_key, curve_p);
    
    std::cout << "私钥: " << private_key << std::endl;
    std::cout << "公钥: (" << public_key.x << ", " << public_key.y << ")" << std::endl;
    
    // 2. 加密消息
    uint64_t message = 1314520; 
    auto ciphertext = ecc_encrypt(public_key, message, curve_p);
    
    std::cout << "加密结果: C1=(" << ciphertext[0] << ", " << ciphertext[1] 
              << "), C2=" << ciphertext[2] << std::endl;
    
    // 3. 解密消息
    uint64_t decrypted = ecc_decrypt(private_key, ciphertext, curve_p);
    
    std::cout << "解密结果: " << decrypted << std::endl;
    std::cout << (decrypted == message ? "解密成功" : "解密失败") << std::endl;
    
    return 0;
}