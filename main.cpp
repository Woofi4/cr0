#include "utils/fileIO.h"
#include "algorithm/AES.h"

#include <iostream>
#include <filesystem>
#include <time.h>


void Encrypt(const char* filepath, const uint8_t key[]) {
    clock_t start = clock();
    uint32_t size;

    int8_t* data0 = Read(filepath, size);
    if (!data0) {
        std::cout << "File not found or busy" << std::endl;
        return;
    }

    int8_t* data = Encrypt(data0, size, key);

    bool status = Write(filepath, data, size);
    std::cout << filepath << " Encrypt - " << (status ? "Done" : "Fail") << " in (" << ((double) (clock() - start) / CLOCKS_PER_SEC) << "s)" <<  std::endl;

    delete[] data, data0;
}

void Decrypt(const char* filepath, const uint8_t key[]) {
    clock_t start = clock();
    uint32_t size;

    int8_t* data = Read(filepath, size);
    if (!data) {
        std::cout << "File not found or busy" << std::endl;
        return;
    }

    int8_t* data0 = Decrypt(data, size, key);

    bool status = Write(filepath, data0, size);
    std::cout << filepath << " Decrypt - " << (status ? "Done" : "Fail") << " in (" << ((double) (clock() - start) / CLOCKS_PER_SEC) << "s)" <<  std::endl;

    delete[] data, data0;
}

void EncryptAll(const char* filepath, const uint8_t key[]) {
    for (const auto& file : std::filesystem::recursive_directory_iterator(filepath)) {
        Encrypt(file.path().string().c_str(), key);
    }
}

void DecryptAll(const char* filepath, const uint8_t key[]) {
    for (const auto& file : std::filesystem::recursive_directory_iterator(filepath)) {
        Decrypt(file.path().string().c_str(), key);
    }
}

int main(int32_t argc, const char* argv[]) {
    if (argc != 4) {
        std::cout << "Wrong arguments. Should be [path] [-e or -d] [key]" << std::endl;
        return -1;
    }

    if (strlen(argv[3]) != 16) {
        std::cout << "Key length should be 16"; // 24 or 32 (soon)
        return -1;
    }

    if (!strcmp(argv[2], "-e")) {
        if (std::filesystem::is_directory(argv[1])) {
            EncryptAll(argv[1], reinterpret_cast<const uint8_t*>(argv[3]));
        } else {
            Encrypt(argv[1], reinterpret_cast<const uint8_t*>(argv[3]));
        }
    } else if (!strcmp(argv[2], "-d")) {
        if (std::filesystem::is_directory(argv[1])) {
            DecryptAll(argv[1], reinterpret_cast<const uint8_t*>(argv[3]));
        } else {
            Decrypt(argv[1], reinterpret_cast<const uint8_t*>(argv[3]));
        }
    } else {
        std::cout << "Unknown mode argument" << std::endl;
        return -1;
    }
    
    return 0;
}