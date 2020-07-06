
#include <iomanip>
#include <iostream>
#include <string>

#include "openssl/evp.h"
const int kDataLen = 64;
int main() {
    uint8_t data[kDataLen] = {
            0x99, 0xc7, 0x4b, 0xb0, 0xcf, 0x1d, 0x83, 0xf8, 0x58, 0x71, 0x41,
            0x9e, 0x2c, 0x60, 0xb8, 0xf0, 0x91, 0xa2, 0x26, 0xea, 0x33, 0x60,
            0xa4, 0xb2, 0xf8, 0x15, 0x98, 0xbc, 0x9b, 0x86, 0x1a, 0x18, 0x2c,
            0x8c, 0x05, 0x17, 0x88, 0x3e, 0x72, 0x73, 0x65, 0x24, 0x13, 0x70,
            0x41, 0xf3, 0x2a, 0xea, 0xf7, 0x09, 0x42, 0x5c, 0xe4, 0x24, 0x41,
            0x2d, 0x9f, 0x6c, 0xf3, 0x12, 0xed, 0xd3, 0x2c, 0xc3};

    std::string key = "MAXHUB";
    const std::string iv = "123145678";

    auto cipher = EVP_sm4_cbc();
    auto ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, (uint8_t*) key.c_str(),
                       (uint8_t*) iv.data());
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int out_len;
    uint8_t* buffer = new uint8_t[kDataLen];
    auto ret = EVP_DecryptUpdate(ctx, buffer, &out_len, data, kDataLen);
    std::cout << out_len << std::endl;

    for (size_t i = 0; i < out_len; i++) {
        std::cout << std::hex << static_cast<int32_t>(buffer[i]);
    }
    std::cout << std::endl;

    delete[] buffer;

    return 0;
}