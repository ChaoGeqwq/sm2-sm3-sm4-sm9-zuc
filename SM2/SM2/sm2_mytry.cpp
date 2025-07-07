#include <iostream>
#include <vector>
#include <cstring>
#include <random>

// ʾ����������Բ���߲�������SM2�Ƽ�����Ϊ����
struct ECPoint {
    uint64_t x;
    uint64_t y;
};

struct SM2Key {
    uint64_t private_key;
    ECPoint public_key;
};

// ��Բ���߲������򻯰棩
const uint64_t P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF; // ����P
const uint64_t A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC; // ����A
const uint64_t B = 0x28E9FA9E9D9F5E344D5AEF6B7FC7C297FDFC7E7E7E7E7E7E7E7E7E7E7E7E7E7E; // ����B
const ECPoint G = {0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7, 
                   0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0}; // ����G
const uint64_t N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123; // ��N

// ��Բ���߼ӷ����򻯰棩
ECPoint ec_add(const ECPoint &p1, const ECPoint &p2) {
    if (p1.x == 0 && p1.y == 0) return p2; // P1������Զ��
    if (p2.x == 0 && p2.y == 0) return p1; // P2������Զ��

    uint64_t lambda;
    if (p1.x == p2.x && p1.y == p2.y) {
        // ����б�� �� = (3 * x1^2 + a) / (2 * y1) mod p
        lambda = (3 * p1.x * p1.x + A) / (2 * p1.y);
    } else {
        // ����б�� �� = (y2 - y1) / (x2 - x1) mod p
        lambda = (p2.y - p1.y) / (p2.x - p1.x);
    }

    uint64_t x3 = (lambda * lambda - p1.x - p2.x) % P;
    uint64_t y3 = (lambda * (p1.x - x3) - p1.y) % P;

    return {x3, y3};
}

// ��Բ���߱����˷����򻯰棩
ECPoint ec_mul(uint64_t k, const ECPoint &p) {
    ECPoint result = {0, 0}; // ����Զ��
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

// ��Կ����
bool sm2_key_generate(SM2Key &key) {
    // ����˽Կ���������
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, N - 1);
    key.private_key = dis(gen);

    // ���ɹ�Կ��˽Կ * ���㣩
    key.public_key = ec_mul(key.private_key, G);
    return true;
}

// ����
bool sm2_encrypt(const SM2Key &key, const uint8_t *plaintext, size_t plaintext_len,
                 uint8_t *ciphertext, size_t &ciphertext_len) {
    // �򻯰棺��չʾ�������̿��
    if (plaintext_len == 0) return false;

    // ���������k
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, N - 1);
    uint64_t k = dis(gen);

    // ������Բ���ߵ�C1 = k * G
    ECPoint C1 = ec_mul(k, G);

    // ���㹲����Կ k * PublicKey
    ECPoint shared_key = ec_mul(k, key.public_key);

    // �򻯣���������Կ��x������Ϊ������Կ
    uint64_t encryption_key = shared_key.x;

    // ��������
    for (size_t i = 0; i < plaintext_len; ++i) {
        ciphertext[i] = plaintext[i] ^ (encryption_key & 0xFF);
        encryption_key >>= 8;
    }

    ciphertext_len = plaintext_len;
    return true;
}

// ����
bool sm2_decrypt(const SM2Key &key, const uint8_t *ciphertext, size_t ciphertext_len,
                 uint8_t *plaintext, size_t &plaintext_len) {
    if (ciphertext_len == 0) return false;

    // ���㹲����Կ PrivateKey * C1
    ECPoint shared_key = ec_mul(key.private_key, {1, 2}); // ����C1��֪

    // �򻯣���������Կ��x������Ϊ������Կ
    uint64_t decryption_key = shared_key.x;

    // ��������
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

    // ������Կ��
    if (!sm2_key_generate(key)) {
        std::cerr << "��Կ����ʧ�ܣ�" << std::endl;
        return -1;
    }

    // ��ӡ˽Կ�͹�Կ
    std::cout << "˽Կ: " << key.private_key << std::endl;
    std::cout << "��Կ: (" << key.public_key.x << ", " << key.public_key.y << ")" << std::endl;

    // ����
    if (!sm2_encrypt(key, plaintext, sizeof(plaintext) - 1, ciphertext, ciphertext_len)) {
        std::cerr << "����ʧ�ܣ�" << std::endl;
        return -1;
    }

    std::cout << "���ܳɹ���" << std::endl;

    // ����
    if (!sm2_decrypt(key, ciphertext, ciphertext_len, decrypted, decrypted_len)) {
        std::cerr << "����ʧ�ܣ�" << std::endl;
        return -1;
    }

    std::cout << "���ܳɹ���" << std::endl;
    std::cout << "���ܽ��: " << std::string(decrypted, decrypted + decrypted_len) << std::endl;

    return 0;
}
