#include <iostream>
#include <cstring>
#include <cstdint>

class SM3 {
private:
    static const uint32_t IV[8];
    static const uint32_t T[64];

    uint32_t W[68];
    uint32_t W1[64];
    uint32_t V[8];

    static uint32_t rotateLeft(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
    }

    static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        return (j < 16) ? (x ^ y ^ z) : ((x & y) | (~x & z));
    }

    static uint32_t P0(uint32_t x) {
        return x ^ rotateLeft(x, 9) ^ rotateLeft(x, 17);
    }

    static uint32_t P1(uint32_t x) {
        return x ^ rotateLeft(x, 15) ^ rotateLeft(x, 23);
    }

    void messageExtension(const uint8_t* block) {
        for (int i = 0; i < 16; ++i) {
            W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }
        for (int i = 16; i < 68; ++i) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ rotateLeft(W[i - 3], 15)) ^ rotateLeft(W[i - 13], 7) ^ W[i - 6];
        }
        for (int i = 0; i < 64; ++i) {
            W1[i] = W[i] ^ W[i + 4];
        }
    }

    void compress(const uint8_t* block) {
        messageExtension(block);

        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t SS1 = rotateLeft(rotateLeft(A, 12) + E + rotateLeft(T[j], j), 7);
            uint32_t SS2 = SS1 ^ rotateLeft(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = rotateLeft(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotateLeft(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A;
        V[1] ^= B;
        V[2] ^= C;
        V[3] ^= D;
        V[4] ^= E;
        V[5] ^= F;
        V[6] ^= G;
        V[7] ^= H;
    }

public:
    SM3() {
        std::memcpy(V, IV, sizeof(IV));
    }

    void update(const uint8_t* data, size_t len) {
        size_t blocks = len / 64;
        for (size_t i = 0; i < blocks; ++i) {
            compress(data + i * 64);
        }
    }

    void finalize(uint8_t* hash) {
        for (int i = 0; i < 8; ++i) {
            hash[i * 4] = (V[i] >> 24) & 0xFF;
            hash[i * 4 + 1] = (V[i] >> 16) & 0xFF;
            hash[i * 4 + 2] = (V[i] >> 8) & 0xFF;
            hash[i * 4 + 3] = V[i] & 0xFF;
        }
    }
};

const uint32_t SM3::IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

const uint32_t SM3::T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

int main() {
    SM3 sm3;
    const char* message = "abc";
    uint8_t hash[32] = {0};

    sm3.update(reinterpret_cast<const uint8_t*>(message), std::strlen(message));
    sm3.finalize(hash);

    std::cout << "SM3 Hash: ";
    for (int i = 0; i < 32; ++i) {
        printf("%02x", hash[i]);
    }
    std::cout << std::endl;

    return 0;
}