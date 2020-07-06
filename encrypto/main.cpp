
#include <iomanip>
#include <iostream>
#include <string>

#include "openssl/evp.h"
const int kDataLen = 64;
int main() {
    uint8_t data[kDataLen] = {'\0'};

    for (size_t i = 0; i < kDataLen; i++) {
        /* code */
        data[i] = '\1';
    }

    std::string key = "MAXHUB";
    const std::string iv = "123145678";

    auto cipher = EVP_sm4_cbc();
    auto ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, (uint8_t*) key.c_str(),
                       (uint8_t*) iv.data());
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int out_len;
    uint8_t* buffer = new uint8_t[kDataLen];
    auto ret = EVP_EncryptUpdate(ctx, buffer, &out_len, data, kDataLen);
    std::cout << out_len << std::endl;

    for (size_t i = 0; i < out_len; i++) {
        std::cout << "0x";
        /* code */
        std::cout << std::setw(2) << std::setfill('0') << std::hex
                  << static_cast<int32_t>(buffer[i]);

        std::cout << ",";
    }
    std::cout << std::endl;

    delete[] buffer;

    return 0;
}
