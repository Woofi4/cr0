#pragma once

#include <fstream>
#include <cstdint>


int8_t* Read(const char* filepath, uint32_t& size);

bool Write(const char* filepath, int8_t* data, uint32_t size);