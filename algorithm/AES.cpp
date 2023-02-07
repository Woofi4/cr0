#include "AES.h"


void AddRoundKey(uint8_t state[4][Nb], uint8_t* key) {
    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t j = 0; j < Nb; ++j) {
            state[i][j] ^= key[i + 4 * j];
        }
    }
}

void SubBytes(uint8_t state[4][Nb]) {
    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t j = 0; j < Nb; ++j) {
            state[i][j] = Sbox[state[i][j] / 16][state[i][j] % 16];
        }
    }
}

void InvSubBytes(uint8_t state[4][Nb]) {
    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t j = 0; j < Nb; ++j) {
            state[i][j] = InvSbox[state[i][j] / 16][state[i][j] % 16];
        }
    }
}

void ShiftRow(uint8_t row[Nb], uint32_t n) {
    uint8_t tmp[Nb];
    for (uint32_t i = 0; i < Nb; ++i) {
        tmp[i] = row[(n + i) % Nb];
    }
    memcpy(row, tmp, Nb);
}

void ShiftRows(uint8_t state[4][Nb]) {
    ShiftRow(state[1], 1);
    ShiftRow(state[2], 2);
    ShiftRow(state[3], 3);
}

void InvShiftRows(uint8_t state[4][Nb]) {
    ShiftRow(state[1], Nb - 1);
    ShiftRow(state[2], Nb - 2);
    ShiftRow(state[3], Nb - 3);
}

void MixColumns(uint8_t state[4][Nb]) {
    uint8_t tmp[4][Nb] = {};
    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t k = 0; k < 4; ++k) {
            if (CMDS[i][k]) {
                for (uint32_t j = 0; j < Nb; ++j) {
                    tmp[i][j] ^= GFTable[CMDS[i][k]][state[k][j]];
                }
            } else {
                for (uint32_t j = 0; j < Nb; ++j) {
                    tmp[i][j] ^= state[k][j]; 
                }
            }
        }
    }
    memcpy(state, tmp, 4 * Nb);
}

void InvMixColumns(uint8_t state[4][Nb]) {
    uint8_t tmp[4][Nb] = {};
    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t k = 0; k < 4; ++k) {
            for (uint32_t j = 0; j < Nb; ++j) {
                tmp[i][j] ^= GFTable[InvCMDS[i][k]][state[k][j]];
            }
        }
    }
    memcpy(state, tmp, 4 * Nb);
}

void EncryptBlock(const int8_t data0[], int8_t data[], uint8_t* w) {
    uint8_t state[4][Nb];
    uint32_t i, j;

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < Nb; ++j) {
            state[i][j] = data0[i + 4 * j];
        }
    }

    AddRoundKey(state, w);
    for (uint32_t r = 1; r < Nr; ++r) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, w + 4 * Nb * r);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, w + 4 * Nb * Nr);

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < Nb; ++j) {
            data[i + 4 * j] = state[i][j];
        }
    }
}

void DecryptBlock(const int8_t data[], int8_t data0[], uint8_t* w) {
    uint8_t state[4][Nb];
    uint32_t i, j;

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < Nb; ++j) {
            state[i][j] = data[i + 4 * j];
        }
    }

    AddRoundKey(state, w + 4 * Nb * Nr);
    for (uint32_t r = Nr - 1; r > 0; --r) {
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, w + 4 * Nb * r);
        InvMixColumns(state);
    }
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, w);

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < Nb; ++j) {
            data0[i + 4 * j] = state[i][j];
        }
    }
}

//

void RotWord(uint8_t x[4]) {
    uint8_t tmp = x[0];
    x[0] = x[1];
    x[1] = x[2];
    x[2] = x[3];
    x[3] = tmp;
}

void SubWord(uint8_t x[4]) {
    for (uint32_t i = 0; i < 4; ++i) {
        x[i] = Sbox[x[i] / 16][x[i] % 16];
    }
}

uint8_t xtime(uint8_t b) {
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void Rcon(uint8_t x[4], uint32_t n) {
    uint8_t b = 1;
    for (uint32_t i = 1; i < n; ++i) {
        b = xtime(b);
    }

    x[0] = b;
    x[1] = x[2] = x[3] = 0;
}

void XorWords(uint8_t x[4], uint8_t y[4]) {
    for (uint32_t i = 0; i < 4; ++i) {
        x[i] ^= y[i];
    }
}

void KeyExpansion(const uint8_t key[], uint8_t w[]) {
    uint8_t tmp[4], rcon[4];
    uint32_t i;

    for (i = 0; i < 4 * Nk; ++i) {
        w[i] = key[i];
    }

    for (i = 4 * Nk; i < 4 * Nb * (Nr + 1); i += 4) {
        tmp[0] = w[i - 4];
        tmp[1] = w[i - 3];
        tmp[2] = w[i - 2];
        tmp[3] = w[i - 1];

        if ((i / 4) % Nk == 0) {
            RotWord(tmp);
            SubWord(tmp);
            Rcon(rcon, i / (Nk * 4));
            XorWords(tmp, rcon);
        } else if (Nk > 6 && (i / 4) & Nk == 4) {
            SubWord(tmp);
        }

        w[i] = w[i - 4 * Nk] ^ tmp[0];
        w[i + 1] = w[i - 4 * Nk + 1] ^ tmp[1];
        w[i + 2] = w[i - 4 * Nk + 2] ^ tmp[2];
        w[i + 3] = w[i - 4 * Nk + 3] ^ tmp[3];
    }
}

//

int8_t* Encrypt(const int8_t* data0, uint32_t size, const uint8_t key[]) {
    int8_t* data = new int8_t[size];
    uint8_t w[4 * Nb * (Nr + 1)];
    KeyExpansion(key, w);
    for (uint32_t i = 0; i < size; i += blockSize) {
        EncryptBlock(data0 + i, data + i, w);
    }

    return data;
}

int8_t* Decrypt(const int8_t* data, uint32_t size, const uint8_t key[]) {
    int8_t* data0 = new int8_t[size];
    uint8_t w[4 * Nb * (Nr + 1)];
    KeyExpansion(key, w);
    for (uint32_t i = 0; i < size; i += blockSize) {
        DecryptBlock(data + i, data0 + i, w);
    }

    return data0;
}