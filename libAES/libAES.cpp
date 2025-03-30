#include <vector>
#include <stdint.h>
#include "libAES.h"

using namespace std;

void libAES::sBox(vector<uint8_t>& block)
{
    for(int i = 0; i < 16; i++)
    {
        block[i] = SBox_consts[block[i]];
    }
}


void libAES::shiftRows(vector<uint8_t>& block)
{
    vector<uint8_t> subBlock;
    for (int i = 1; i < 4; i++)
    {
        subBlock = {block[i], block[i + 4], block[i + 8], block[i + 12]};
        subBlock = rotate(subBlock, i);

        block[i] = subBlock[0];
        block[i + 4] = subBlock[1];
        block[i + 8] = subBlock[2];
        block[i + 12] = subBlock[3];
    }

}


void libAES::mixColumns(vector<uint8_t>& block) {
    vector<uint8_t> tempBlock = block;
    const uint8_t mixMatrix[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };

    for (int col = 0; col < 4; ++col) {
        for (int row = 0; row < 4; ++row) {
            block[col * 4 + row] =
                gfMult(tempBlock[col * 4 + 0], mixMatrix[row][0]) ^
                gfMult(tempBlock[col * 4 + 1], mixMatrix[row][1]) ^
                gfMult(tempBlock[col * 4 + 2], mixMatrix[row][2]) ^
                gfMult(tempBlock[col * 4 + 3], mixMatrix[row][3]);
        }
    }
}


void libAES::addRoundKey(vector<uint8_t>& block, const vector<uint8_t>& key)
{
    for(int i = 0; i < 16; i++)
    {
        block[i] = block[i] ^ key[i];
    }
}


vector<uint8_t> libAES::rotate(vector<uint8_t>& subBlock, int num_rots)
{
    uint8_t front;
    for (int i = 0; i < num_rots; i++)
    {
        front = subBlock.front();
        subBlock.erase(subBlock.begin());
        subBlock.push_back(front);
    }
    return subBlock;
}


uint8_t libAES::gfMult(uint8_t data, uint8_t multiplier)
{
    uint8_t temp;
    switch (multiplier)
    {
        case 0x01:
            return data;

        case 0x02:
            temp = (data << 1) & 0xFE;
            if(data & (1 << 7))
            {
                temp = temp ^ 0x1b;
            }
            return temp;

        case 0x03:
            return gfMult(data, 0x02) ^ data;

        default:
            return 0x00;
    }
}

vector<uint8_t> libAES::calcRoundKey128(vector<uint8_t>& key, vector<uint8_t>& Gn, int round)
{
    uint8_t Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    vector<uint8_t> tail = {key[13], key[14], key[15], key[12]};
    
    for (int i = 0; i < 4; i++) {
        tail[i] = SBox_consts[tail[i]];
    }

    tail[0] ^= Rcon[round - 1];

    for(int i = 0; i < 4; i++) {
        key[i] ^= tail[i];
    }

    for(int i = 4; i < 16; i++) {
        key[i] ^= key[i-4];
    }

    return tail;
}