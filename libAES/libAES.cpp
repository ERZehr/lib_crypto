#include <vector>
#include <stdint.h>
#include <iomanip>
#include <sstream>
#include <iostream>
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
            temp = (data << 1);
            if (data & 0x80)
            {
                temp ^= 0x1b;
            }
            return temp & 0xFF;

        case 0x03:
            return gfMult(data, 0x02) ^ data;

        case 0x09:
            return gfMult(gfMult(gfMult(data, 0x02), 0x02), 0x02) ^ data;

        case 0x0b:
            return gfMult(gfMult(gfMult(data, 0x02), 0x02), 0x02) ^ gfMult(data, 0x02) ^ data;

        case 0x0d:
            return gfMult(gfMult(gfMult(data, 0x02), 0x02), 0x02) ^ gfMult(gfMult(data, 0x02), 0x02) ^ data;

        case 0x0e:
            return gfMult(gfMult(gfMult(data, 0x02), 0x02), 0x02) ^ gfMult(gfMult(data, 0x02), 0x02) ^ gfMult(data, 0x02);

        default:
            return 0x00;
    }
}


void libAES::calcRoundKey128(vector<uint8_t>& key, int round)
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
}


void libAES::calcRoundKey192(vector<uint8_t>& key, int round)
{
    uint8_t Rcon[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    vector<uint8_t> tail = {key[21], key[22], key[23], key[20]};

    for (int i = 0; i < 4; i++) {
        tail[i] = SBox_consts[tail[i]];
    }

    tail[0] ^= Rcon[round - 1];

    for(int i = 0; i < 4; i++) {
        key[i] ^= tail[i];
    }

    for(int i = 4; i < 24; i++) {
        key[i] ^= key[i-4];
    }
}


void libAES::calcRoundKey256(vector<uint8_t>& key, int round)
{
    uint8_t Rcon[7] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};
    vector<uint8_t> tail = {key[29], key[30], key[31], key[28]};

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

    for (int i = 16; i < 20; i++) {
        key[i] ^= SBox_consts[key[i-4]];
    }

    for(int i = 20; i < 32; i++) {
        key[i] ^= key[i-4];
    }
}


void libAES::aes128(vector<uint8_t>& block, vector<uint8_t>& key)
{
    libAES AES;
    AES.addRoundKey(block, key);

    for(int i = 1; i < 10; i++)
    {
        AES.sBox(block);
        AES.shiftRows(block);
        AES.mixColumns(block);
        AES.calcRoundKey128(key, i);
        AES.addRoundKey(block, key);
    }

    AES.sBox(block);
    AES.shiftRows(block);
    AES.calcRoundKey128(key, 10);
    AES.addRoundKey(block, key);
}


void libAES::aes192(vector<uint8_t>& block, vector<uint8_t>& key)
{
    libAES AES;

    vector<uint8_t> round_key; // spliced key
    int index; // index of calculated key
    int key_counter = 1; // pseudo round number ofr key calculation

    // round 0
    for (index = 0; index < 16; index++)
    {
        round_key.push_back(key[index]);
    }
    AES.addRoundKey(block, round_key);
    round_key.clear();

    // intermediate key splitting (rounds 1-11)
    for(int i = 1; i < 12; i++)
    {
        AES.sBox(block);
        AES.shiftRows(block);
        AES.mixColumns(block);

        if(index == 0) // generate new, use first 4 words
        {
            AES.calcRoundKey192(key, key_counter++);
            for (index = 0; index < 16; index++)
            {
                round_key.push_back(key[index]);
            }
        }
        else if (index == 8) // use last 4 words
        {
            for (index = 8; index < 24; index++)
            {
                round_key.push_back(key[index]);
            }
            index = 0;
        }
        else // use last 2 words, generate new, user first 2 words
        {
            for (index = 16; index < 24; index++)
            {
                round_key.push_back(key[index]);
            }
            index = 0;
            AES.calcRoundKey192(key, key_counter++);
            for (index = 0; index < 8; index++)
            {
                round_key.push_back(key[index]);
            }
        }
        AES.addRoundKey(block, round_key);
        round_key.clear();
    }

    // round 12
    AES.sBox(block);
    AES.shiftRows(block);
    AES.calcRoundKey192(key, key_counter++);
    for (index = 0; index < 16; index++)
    {
        round_key.push_back(key[index]);
    }
    AES.addRoundKey(block, round_key);
    
}


void libAES::aes256(vector<uint8_t>& block, vector<uint8_t>& key)
{
    libAES AES;

    vector<uint8_t> round_key; // spliced key
    int index; // index of calculated key
    int key_counter = 1; // pseudo round number ofr key calculation

    // round 0
    for (index = 0; index < 16; index++)
    {
        round_key.push_back(key[index]);
    }
    AES.addRoundKey(block, round_key);
    round_key.clear();

    // intermediate key splitting (rounds 1-11)
    for(int i = 1; i < 14; i++)
    {
        AES.sBox(block);
        AES.shiftRows(block);
        AES.mixColumns(block);
    
        if(index == 0) // generate new, use first 4 words
        {
            AES.calcRoundKey256(key, key_counter++);
            for (index = 0; index < 16; index++)
            {
                round_key.push_back(key[index]);
            }
        }
        else // use last 4 words
        {
            for (index = 16; index < 32; index++)
            {
                round_key.push_back(key[index]);
            }
            index = 0;
        }
        AES.addRoundKey(block, round_key);
        round_key.clear();
    }

    // round 14
    AES.sBox(block);
    AES.shiftRows(block);
    AES.calcRoundKey256(key, key_counter++);
    for (index = 0; index < 16; index++)
    {
        round_key.push_back(key[index]);
    }
    AES.addRoundKey(block, round_key);
}




void libAES::sBoxInv(vector<uint8_t>& block)
{
    for(int i = 0; i < 16; i++)
    {
        block[i] = SBox_constsInv[block[i]];
    }
}


void libAES::shiftRowsInv(vector<uint8_t>& block)
{
    vector<uint8_t> subBlock;
    for (int i = 1; i < 4; i++)
    {
        subBlock = {block[i], block[i + 4], block[i + 8], block[i + 12]};
        subBlock = rotate(subBlock, 4-i);

        block[i]     = subBlock[0];
        block[i + 4] = subBlock[1];
        block[i + 8] = subBlock[2];
        block[i + 12] = subBlock[3];
    }
}


void libAES::mixColumnsInv(vector<uint8_t>& block)
{
    vector<uint8_t> tempBlock = block;
    const uint8_t mixMatrix[4][4] = {
        {0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}
    };

    for (int col = 0; col < 4; ++col) {
        for (int row = 0; row < 4; ++row) {
            block[row + col * 4] = 
                gfMult(tempBlock[col * 4 + 0], mixMatrix[row][0]) ^
                gfMult(tempBlock[col * 4 + 1], mixMatrix[row][1]) ^
                gfMult(tempBlock[col * 4 + 2], mixMatrix[row][2]) ^
                gfMult(tempBlock[col * 4 + 3], mixMatrix[row][3]);
        }
    }
}


vector<uint8_t> libAES::rotateInv(vector<uint8_t>& subBlock, int num_rots)
{
    uint8_t end;
    for (int i = 0; i < num_rots; i++)
    {
        end = subBlock[subBlock.size() - 1];
        for (int j = subBlock.size() - 1; j > 0; j--)
        {
            subBlock[j] = subBlock[j - 1];
        }
        subBlock[0] = end;
    }
    return subBlock;
}


void libAES::calcRoundKey128Inv(vector<uint8_t>& key, int round)
{
    uint8_t Rcon[10] = {0x36, 0x1B, 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
    vector<uint8_t> tail;

    for(int i = 16; i > 3; i--) {
        key[i] ^= key[i-4];
    }

    tail = {key[13], key[14], key[15], key[12]};

    for (int i = 3; i >= 0; i--) {
        tail[i] = SBox_consts[tail[i]];
    }

    tail[0] ^= Rcon[round - 1];

    for(int i = 3; i >= 0; i--) {
        key[i] ^= tail[i];
    }
}


void libAES::calcRoundKey192Inv(vector<uint8_t>& key, int round)
{
    uint8_t Rcon[8] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
    vector<uint8_t> tail;

    for(int i = 23; i > 3; i--) {
        key[i] ^= key[i-4];
    }

    tail = {key[21], key[22], key[23], key[20]};

    for (int i = 3; i >= 0; i--) {
        tail[i] = SBox_consts[tail[i]];
    }

    tail[0] ^= Rcon[round - 1];

    for(int i = 3; i >= 0; i--) {
        key[i] ^= tail[i];
    }
}


void libAES::calcRoundKey256Inv(vector<uint8_t>& key, int round)
{
    uint8_t Rcon[7] = {0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
    vector<uint8_t> tail;

    for(int i = 31; i > 19; i--) {
        key[i] ^= key[i-4];
    }

    for (int i = 19; i > 15; i--) {
        key[i] ^= SBox_consts[key[i-4]];
    }

    for(int i = 15; i > 3; i--) {
        key[i] ^= key[i-4];
    }

    tail = {key[29], key[30], key[31], key[28]};

    for (int i = 3; i >= 0; i--) {
        tail[i] = SBox_consts[tail[i]];
    }

    tail[0] ^= Rcon[round - 1];

    for(int i = 3; i >= 0; i--) {
        key[i] ^= tail[i];
    }
}


void libAES::aes128Inv(vector<uint8_t>& block, vector<uint8_t>& key)
{
    libAES AES;

    for(int i = 1; i <= 10; i++)
    {
        AES.calcRoundKey128(key, i);
    }

    AES.addRoundKey(block, key);
    AES.calcRoundKey128Inv(key, 1);
    AES.shiftRowsInv(block);
    AES.sBoxInv(block);

    for(int i = 2; i <= 10; i++)
    {
        AES.addRoundKey(block, key);
        AES.calcRoundKey128Inv(key, i);
        AES.mixColumnsInv(block);
        AES.shiftRowsInv(block);
        AES.sBoxInv(block);
    }

    AES.addRoundKey(block, key);
}


void libAES::aes192Inv(vector<uint8_t>& block, vector<uint8_t>& key)
{

    libAES AES;
    vector<uint8_t> round_key; // spliced key
    int index; // index of calculated key
    int key_counter = 1; // pseudo round number ofr key calculation

    for(int i = 1; i <= 8; i++) // get end key
    {
        AES.calcRoundKey192(key, i);
    }

    for (index = 0; index < 16; index++) // get first 4 of last roll
    {
        round_key.push_back(key[index]);
    }
    AES.addRoundKey(block, round_key);
    index = 23; // set our index to the end
    AES.shiftRowsInv(block);
    AES.sBoxInv(block);

    for(int i = 1; i < 12; i++)
    {
        round_key.clear();

        if(index == 23) // generate new, use last 4 words
        {
            AES.calcRoundKey192Inv(key, key_counter++);

            for (index = 8; index < 24; index++)
            {
                round_key.push_back(key[index]);
            }
            index = 7;
        }
        else if (index == 7) // save first 2, generate new, append first 2 to last 2
        {
            for (index = 0; index < 8; index++)
            {
                round_key.push_back(key[index]);
            }
            AES.calcRoundKey192Inv(key, key_counter++);

            for (index = 16; index < 24; index++)
            {
                round_key.insert(round_key.begin(), (key[index]));
            }
            uint8_t temp;
            for(int i = 0; i < 4; i++)
            {
                temp = round_key[i];
                round_key[i] = round_key[7 - i];
                round_key[7 - i] = temp;
            }
            index = 15;
        }
        else // index == 15, use first 4 words
        {
            for (index = 0; index < 16; index++)
            {
                round_key.push_back(key[index]);
            }
            index = 23;
        }
        AES.addRoundKey(block, round_key);
        AES.mixColumnsInv(block);
        AES.shiftRowsInv(block);
        AES.sBoxInv(block);
    }

    round_key.clear();
    for (index = 0; index < 16; index++) // get first 4 of original key
    {
        round_key.push_back(key[index]);
    }
    AES.addRoundKey(block, round_key);
}


void libAES::aes256Inv(vector<uint8_t>& block, vector<uint8_t>& key)
{
    libAES AES;

    vector<uint8_t> round_key; // spliced key
    int index; // index of calculated key
    int key_counter = 1; // pseudo round number ofr key calculation

    for(int i = 1; i <= 7; i++) // get end key
    {
        AES.calcRoundKey256(key, i);
    }

    for (index = 0; index < 16; index++)
    {
        round_key.push_back(key[index]);
    }

    AES.addRoundKey(block, round_key);
    index = 31;
    AES.shiftRowsInv(block);
    AES.sBoxInv(block);

    for(int i = 1; i < 14; i++)
    {
        round_key.clear();
    
        if(index == 31) // generate new, use last 4 words
        {
            AES.calcRoundKey256Inv(key, key_counter++);
            for (index = 16; index < 32; index++)
            {
                round_key.push_back(key[index]);
            }
            index = 15;
        }
        else // index == 15,  use first 4 words
        {
            for (index = 0; index < 16; index++)
            {
                round_key.push_back(key[index]);
            }
            index = 31;
        }

        AES.addRoundKey(block, round_key);
        AES.mixColumnsInv(block);
        AES.shiftRowsInv(block);
        AES.sBoxInv(block);
    }

    round_key.clear();
    for (index = 0; index < 16; index++)
    {
        round_key.push_back(key[index]);
    }
    AES.addRoundKey(block, round_key);
}





void libAES::aesECB(vector<uint8_t>& block, vector<uint8_t>& key, bool enc_dec)
{
    libAES AES;
    if(!enc_dec) // encryption
    {
        if(key.size() == 16) // 128 bit
        {
            aes128(block, key);
        }
        else if(key.size() == 24) // 192 bit
        {
            aes192(block, key);
        }
        else // 256 bit
        {
            aes256(block, key);
        }
    }
    else // decryption
    {
        if(key.size() == 16) // 128 bit
        {
            aes128Inv(block, key);
        }
        else if(key.size() == 24) // 192 bit
        {
            aes192Inv(block, key);
        }
        else // 256 bit
        {
            aes256Inv(block, key);
        }
    }
}


void libAES::aesCBC(vector<uint8_t>& block, vector<uint8_t>& key, bool enc_dec)
{

}


void libAES::aesCFB(vector<uint8_t>& block, vector<uint8_t>& key, bool enc_dec)
{

}


void libAES::aesOFB(vector<uint8_t>& block, vector<uint8_t>& key, bool enc_dec)
{

}


void libAES::aesCTR(vector<uint8_t>& block, vector<uint8_t>& key, bool enc_dec)
{

}


void libAES::aesGCM(vector<uint8_t>& block, vector<uint8_t>& key, bool enc_dec)
{

}


void libAES::aesXTS(vector<uint8_t>& block, vector<uint8_t>& key, bool enc_dec)
{

}