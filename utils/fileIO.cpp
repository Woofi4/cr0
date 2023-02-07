#include "fileIO.h"


int8_t* Read(const char* filepath, uint32_t& size) {
    std::ifstream stream(filepath, std::ios::binary | std::ios::ate);
    if (!stream) {
        return nullptr;
    }
    
    size = stream.tellg();
    uint32_t padding = (size % 16) ? (16 - (size % 16)) : 0;
    size += padding;

    int8_t* data = new int8_t[size];
    for (uint32_t i = 1; i <= padding; ++i) {
        data[size - i] = 0;
    }

    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(data), size - padding);
    stream.close();

    return data;
}

bool Write(const char* filepath, int8_t* data, uint32_t size) {
    std::ofstream stream(filepath, std::ios::binary);
    if (!stream) {
        return false;
    }

    stream.write(reinterpret_cast<char*>(data), size);
	stream.close();

    return true;
}