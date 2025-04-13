#include <vector>
#include <stdint.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <fstream>
#include "libAES.h"

using namespace std;

void libAES::printBinaryVector(const vector<uint8_t>& binary_data) {
    for (uint8_t byte : binary_data) {
        for (int i = 7; i >= 0; --i) {
            cout << ((byte >> i) & 1);
        }
    }
    cout << endl;
}


void libAES::padBinary(vector<uint8_t>& binary_data)
{
    int padSize = 16 - binary_data.size() % 16;
    if (padSize == 0)
        padSize = 16;

    binary_data.insert(binary_data.end(), padSize, static_cast<uint8_t>(padSize));
}


void libAES::unpadBinary(vector<uint8_t>& binary_data)
{
    if (binary_data.empty())
    {
        return;
    }

    int unpadValue = static_cast<int>(binary_data.back());

    if (unpadValue == 0 || unpadValue > 16 || unpadValue > static_cast<int>(binary_data.size()))
    {
        throw runtime_error("Invalid Padding");
    }

    for (int i = 0; i < unpadValue; ++i)
    {
        if (binary_data[binary_data.size() - 1 - i] != unpadValue)
            throw runtime_error("Invalid Padding");
    }

    binary_data.erase(binary_data.end() - unpadValue, binary_data.end());
}


vector<uint8_t> libAES::fileToBinary(const string& filename) {
    ifstream file(filename, ios::binary);

    if (!file) {
        throw runtime_error("Failed to open file for reading");
    }

    vector<uint8_t> buffer((istreambuf_iterator<char>(file)), {});
    
    file.close();
    return buffer;
}


void libAES::binaryToFile(const vector<uint8_t>& writeVector, const string& filename) {
    ofstream file(filename, ios::binary | ios::trunc);

    if (!file) {
        throw runtime_error("Failed to open file for writing");
    }

    file.write(reinterpret_cast<const char*>(writeVector.data()), writeVector.size());
    
    if (!file) {
        throw runtime_error("Error writing to file");
    }

    file.close();
}


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
    int size = block.size();
    for(int i = 0; i < size; i++)
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


vector<uint8_t> libAES::gfMult128(const vector<uint8_t>& X, const vector<uint8_t>& Y)
{
    vector<uint8_t> Z = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    vector<uint8_t> V = Y;

    for (int i = 0; i < 128; ++i)
    {
        int byte_index = i / 8;
        int bit_index = 7 - (i % 8);
        bool xbit = (X[byte_index] >> bit_index) & 1;

        if (xbit) {
            for (int j = 0; j < 16; ++j)
                Z[j] ^= V[j];
        }

        bool carry = V[15] & 1;
        for (int j = 15; j > 0; --j) {
            V[j] = (V[j] >> 1) | ((V[j - 1] & 0x01) << 7);
        }
        V[0] >>= 1;

        if (carry) {
            V[0] ^= 0xE1;
        }
    }

    return Z;
}


void libAES::aesECB(vector<uint8_t>& binaryData, vector<uint8_t>& key, int enc_dec)
{
    libAES AES;
    vector<uint8_t> block;
    vector<uint8_t> key_saver = key;

    if(!enc_dec) // encryption
    {
        AES.padBinary(binaryData);
        for(int i = 0; i < static_cast<int>(binaryData.size()) / 16; i++)
        {
            key = key_saver;
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            if(key.size() == 16)      // 128 bit
                AES.aes128(block, key);
            else if(key.size() == 24) // 192 bit
                AES.aes192(block, key);
            else if(key.size() == 24) // 256 bit
                AES.aes256(block, key);
            else
                throw runtime_error("Invalid key length.");
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
        }
    }
    else // decryption
    {
        for(int i = 0; i < static_cast<int>(binaryData.size()) / 16; i++)
        {
            key = key_saver;
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            if(key.size() == 16)      // 128 bit
                AES.aes128Inv(block, key);
            else if(key.size() == 24) // 192 bit
                AES.aes192Inv(block, key);
            else if(key.size() == 24) // 256 bit
                AES.aes256Inv(block, key);
            else
                throw runtime_error("Invalid key length.");
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
        }
        AES.unpadBinary(binaryData);
    }
}


void libAES::aesECB(const string& filename, vector<uint8_t>& key, int enc_dec)
{
    libAES AES;
    vector<uint8_t> binaryData = AES.fileToBinary(filename);
    vector<uint8_t> key_saver = key;
    vector<uint8_t> block;

    if(!enc_dec) // encryption
    {
        AES.padBinary(binaryData);
        for(int i = 0; i < static_cast<int>(binaryData.size()) / 16; i++)
        {
            key = key_saver;
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            if(key.size() == 16)      // 128 bit
                AES.aes128(block, key);
            else if(key.size() == 24) // 192 bit
                AES.aes192(block, key);
            else if(key.size() == 32) // 256 bit
                AES.aes256(block, key);
            else
                throw runtime_error("Invalid key length.");
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
        }
    }
    else // decryption
    {
        for(int i = 0; i < static_cast<int>(binaryData.size()) / 16; i++)
        {
            key = key_saver;
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            if(key.size() == 16)      // 128 bit
                AES.aes128Inv(block, key);
            else if(key.size() == 24) // 192 bit
                AES.aes192Inv(block, key);
            else if(key.size() == 32) // 256 bit
                AES.aes256Inv(block, key);
            else
                throw runtime_error("Invalid key length.");
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
        }
        AES.unpadBinary(binaryData);
    }
    AES.binaryToFile(binaryData, filename);
}


void libAES::aesCBC(vector<uint8_t>& binaryData, vector<uint8_t>& key, const vector<uint8_t>& iv, int enc_dec)
{
    libAES AES;
    vector<uint8_t> block;
    vector<uint8_t> key_saver = key;

    if(iv.size() != 16)
        throw runtime_error("Invalid IV length");
    vector<uint8_t> current_iv = iv;


    if(!enc_dec) // encryption
    {
        AES.padBinary(binaryData);

        for(int i = 0; i < static_cast<int>(binaryData.size()) / 16; i++)
        {
            key = key_saver;
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            AES.addRoundKey(block, current_iv); // This is just an XOR, so im reusing it here. 
            if(key.size() == 16)
                AES.aes128(block, key);
            else if(key.size() == 24)
                AES.aes192(block, key);
            else if(key.size() == 32)
                AES.aes256(block, key);
            else
                throw runtime_error("Invalid key length.");
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
            current_iv = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
        }
    }
    else // decryption
    {
        vector<uint8_t> save_cipher;

        for(int i = 0; i < static_cast<int>(binaryData.size()) / 16; i++)
        {
            key = key_saver;
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            save_cipher = block;
            if(key.size() == 16)
                AES.aes128Inv(block, key);
            else if(key.size() == 24) 
                AES.aes192Inv(block, key);
            else if(key.size() == 32)
                AES.aes256Inv(block, key);
            else
                throw runtime_error("Invalid key length.");
            AES.addRoundKey(block, current_iv);
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
            current_iv = save_cipher;
        }
        AES.unpadBinary(binaryData);
    }
}


void libAES::aesCBC(const string& filename, vector<uint8_t>& key, const vector<uint8_t>& iv, int enc_dec)
{
    libAES AES;
    vector<uint8_t> binaryData = AES.fileToBinary(filename);
    vector<uint8_t> key_saver = key;

    if(iv.size() != 16)
        throw runtime_error("Invalid IV length");
    vector<uint8_t> current_iv = iv;
    vector<uint8_t> block;

    if(!enc_dec) // encryption
    {
        AES.padBinary(binaryData);

        for(int i = 0; i < static_cast<int>(binaryData.size()) / 16; i++)
        {
            key = key_saver;
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            AES.addRoundKey(block, current_iv); // This is just an XOR, so im reusing it here. 
            if(key.size() == 16)
                AES.aes128(block, key);
            else if(key.size() == 24)
                AES.aes192(block, key);
            else if(key.size() == 32)
                AES.aes256(block, key);
            else
                throw runtime_error("Invalid key length.");
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
            current_iv = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
        }
    }
    else // decryption
    {
        vector<uint8_t> save_cipher;

        for(int i = 0; i < static_cast<int>(binaryData.size()) / 16; i++)
        {
            key = key_saver;
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            save_cipher = block;
            if(key.size() == 16)
                AES.aes128Inv(block, key);
            else if(key.size() == 24) 
                AES.aes192Inv(block, key);
            else if(key.size() == 32)
                AES.aes256Inv(block, key);
            else
                throw runtime_error("Invalid key length.");
            AES.addRoundKey(block, current_iv);
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
            current_iv = save_cipher;
        }
        AES.unpadBinary(binaryData);
    }
    AES.binaryToFile(binaryData, filename);
}


void libAES::aesCFB(vector<uint8_t>& binaryData, vector<uint8_t>& key, const vector<uint8_t>& iv, int enc_dec)
{
    libAES AES;
    vector<uint8_t> block;
    vector<uint8_t> key_saver = key;

    if(iv.size() != 16)
        throw runtime_error("Invalid IV length");
    vector<uint8_t> current_iv = iv;

    if(!enc_dec) // encryption
    {
        for(int i = 0; i < (static_cast<int>(binaryData.size()) + 15) / 16 ; i++)
        {
            key = key_saver;
            if(key.size() == 16)      // 128 bit
                AES.aes128(current_iv, key);
            else if(key.size() == 24) // 192 bit
                AES.aes192(current_iv, key);
            else if(key.size() == 32)  // 256 bit
                AES.aes256(current_iv, key);
            else
                throw runtime_error("Invalid key length.");

            if(binaryData.begin() + ((i + 1) * 16) < binaryData.end()) // check if we are on a 16 byte block or not
                block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            else
                block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.end());
        
            AES.addRoundKey(block, current_iv);
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
            current_iv = block;
        }
    }
    else // decryption
    {
        vector<uint8_t> save_cipher;

        for(int i = 0; i < (static_cast<int>(binaryData.size()) + 15) / 16 ; i++)
        {
            key = key_saver;
            if(key.size() == 16)      // 128 bit
                AES.aes128(current_iv, key);
            else if(key.size() == 24) // 192 bit
                AES.aes192(current_iv, key);
            else if(key.size() == 32)  // 256 bit
                AES.aes256(current_iv, key);
            else
                throw runtime_error("Invalid key length.");
            
            if(binaryData.begin() + ((i + 1) * 16) < binaryData.end()) // check if we are on a 16 byte block or not
                block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            else
                block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.end());

            save_cipher = block;
            AES.addRoundKey(block, current_iv);
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
            current_iv = save_cipher;
        }
    }
}


void libAES::aesCFB(const string& filename, vector<uint8_t>& key, const vector<uint8_t>& iv, int enc_dec)
{
    libAES AES;
    vector<uint8_t> binaryData = AES.fileToBinary(filename);
    vector<uint8_t> key_saver = key;

    if(iv.size() != 16)
        throw runtime_error("Invalid IV length");
    vector<uint8_t> current_iv = iv;
    vector<uint8_t> block;

    if(!enc_dec) // encryption
    {
        for(int i = 0; i < (static_cast<int>(binaryData.size()) + 15) / 16 ; i++)
        {
            key = key_saver;
            if(key.size() == 16)      // 128 bit
                AES.aes128(current_iv, key);
            else if(key.size() == 24) // 192 bit
                AES.aes192(current_iv, key);
            else if(key.size() == 32)  // 256 bit
                AES.aes256(current_iv, key);
            else
                throw runtime_error("Invalid key length.");
            
            if(binaryData.begin() + ((i + 1) * 16) < binaryData.end()) // check if we are on a 16 byte block or not
                block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            else
                block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.end());

            AES.addRoundKey(block, current_iv);
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
            current_iv = block;
        }
    }
    else // decryption
    {
        vector<uint8_t> save_cipher;

        for(int i = 0; i < (static_cast<int>(binaryData.size()) + 15) / 16 ; i++)
        {
            key = key_saver;
            if(key.size() == 16) // 128 bit
                AES.aes128(current_iv, key);
            else if(key.size() == 24) // 192 bit
                AES.aes192(current_iv, key);
            else if(key.size() == 32)  // 256 bit
                AES.aes256(current_iv, key);// 256 bit
            else
                throw runtime_error("Invalid key length.");

            if(binaryData.begin() + ((i + 1) * 16) < binaryData.end()) // check if we are on a 16 byte block or not
                block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
            else
                block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.end());

            save_cipher = block;
            AES.addRoundKey(block, current_iv);
            copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
            current_iv = save_cipher;
        }
    }
    AES.binaryToFile(binaryData, filename);
}


void libAES::aesOFB(vector<uint8_t>& binaryData, vector<uint8_t>& key, const vector<uint8_t>& iv, int enc_dec)
{
    libAES AES;
    vector<uint8_t> block;
    vector<uint8_t> key_saver = key;

    if(iv.size() != 16)
        throw runtime_error("Invalid IV length");
    vector<uint8_t> current_iv = iv;
    vector<uint8_t> save_new_iv;

    // encryption and decryption are symetric
    for(int i = 0; i < (static_cast<int>(binaryData.size()) + 15) / 16 ; i++)
    {
        key = key_saver;
        if(key.size() == 16)
            AES.aes128(current_iv, key);
        else if(key.size() == 24)
            AES.aes192(current_iv, key);
        else if(key.size() == 32)
            AES.aes256(current_iv, key);
        else
            throw runtime_error("Invalid key length.");

        save_new_iv = current_iv;
        if(binaryData.begin() + ((i + 1) * 16) < binaryData.end()) // check if we are on a 16 byte block or not
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
        else
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.end());
        AES.addRoundKey(block, current_iv);
        copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
        current_iv = save_new_iv;
    }
}


void libAES::aesOFB(const string& filename, vector<uint8_t>& key, const vector<uint8_t>& iv, int enc_dec)
{
    libAES AES;
    vector<uint8_t> binaryData = AES.fileToBinary(filename);
    vector<uint8_t> key_saver = key;
    
    if(iv.size() != 16)
        throw runtime_error("Invalid IV length");
    vector<uint8_t> current_iv = iv;
    vector<uint8_t> block;
    vector<uint8_t> save_new_iv;

    // encryption and decryption are symetric
    for(int i = 0; i < (static_cast<int>(binaryData.size()) + 15) / 16 ; i++)
    {
        key = key_saver;
        if(key.size() == 16)
            AES.aes128(current_iv, key);
        else if(key.size() == 24)
            AES.aes192(current_iv, key);
        else if(key.size() == 32)
            AES.aes256(current_iv, key);
        else
            throw runtime_error("Invalid key length.");

        save_new_iv = current_iv;
        if(binaryData.begin() + ((i + 1) * 16) < binaryData.end()) // check if we are on a 16 byte block or not
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
        else
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.end());
        AES.addRoundKey(block, current_iv);
        copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
        current_iv = save_new_iv;
    }

    AES.binaryToFile(binaryData, filename);
}


void libAES::aesCTR(vector<uint8_t>& binaryData, vector<uint8_t>& key, const vector<uint8_t>& iv, int enc_dec, vector<uint8_t> counter = {0x00,0x00,0x00,0x00})
{
    libAES AES;
    vector<uint8_t> block;
    vector<uint8_t> key_saver = key;
    vector<uint8_t> nonce_counter;
    vector<uint8_t> nonce_counter_saver = iv;
    uint32_t num = (static_cast<uint32_t>(counter[0]) << 24) | (static_cast<uint32_t>(counter[1]) << 16) | (static_cast<uint32_t>(counter[2]) << 8)  | (static_cast<uint32_t>(counter[3]));

    for(int i = 0; i < 4; i ++)
        nonce_counter_saver.push_back(counter[i]);

    for(int i = 0; i < (static_cast<int>(binaryData.size()) + 15) / 16 ; i++)
    {
        key = key_saver;
        nonce_counter = nonce_counter_saver;
        
        if(key.size() == 16)      // 128 bit
            AES.aes128(nonce_counter, key);
        else if(key.size() == 24) // 192 bit
            AES.aes192(nonce_counter, key);
        else if(key.size() == 32)  // 256 bit
            AES.aes256(nonce_counter, key);
        else
            throw runtime_error("Invalid key length.");
        
        if(binaryData.begin() + ((i + 1) * 16) < binaryData.end()) // check if we are on a 16 byte block or not
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
        else
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.end());
        
        AES.addRoundKey(block, nonce_counter);
        copy(block.begin(), block.end(), binaryData.begin() + (i * 16));

        // cumbersome increment of iv
        num++;
        for (int j = 0; j < 4; j++) 
            nonce_counter_saver[iv.size() + j] = num >> ((3 - j) * 8) & 0xFF;
    }
}


void libAES::aesCTR(const string& filename, vector<uint8_t>& key, const vector<uint8_t>& iv, int enc_dec, vector<uint8_t> counter = {0x00,0x00,0x00,0x00})
{
    libAES AES;
    vector<uint8_t> binaryData = AES.fileToBinary(filename);
    vector<uint8_t> block;
    vector<uint8_t> key_saver = key;
    vector<uint8_t> nonce_counter;
    vector<uint8_t> nonce_counter_saver = iv;
    uint32_t num = (static_cast<uint32_t>(counter[0]) << 24) | (static_cast<uint32_t>(counter[1]) << 16) | (static_cast<uint32_t>(counter[2]) << 8)  | (static_cast<uint32_t>(counter[3]));

    for(int i = 0; i < 4; i ++)
        nonce_counter_saver.push_back(counter[i]);

    for(int i = 0; i < (static_cast<int>(binaryData.size()) + 15) / 16 ; i++)
    {
        key = key_saver;
        nonce_counter = nonce_counter_saver;
        
        if(key.size() == 16)      // 128 bit
            AES.aes128(nonce_counter, key);
        else if(key.size() == 24) // 192 bit
            AES.aes192(nonce_counter, key);
        else if(key.size() == 32) // 256 bit
            AES.aes256(nonce_counter, key);
        else 
            throw runtime_error("Invalid key length.");
        
        if(binaryData.begin() + ((i + 1) * 16) < binaryData.end()) // check if we are on a 16 byte block or not
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
        else
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.end());
        
        AES.addRoundKey(block, nonce_counter);
        copy(block.begin(), block.end(), binaryData.begin() + (i * 16));

        // cumbersome increment of iv
        num++;
        for (int j = 0; j < 4; j++) 
            nonce_counter_saver[iv.size() + j] = num >> ((3 - j) * 8) & 0xFF;
    }

    AES.binaryToFile(binaryData, filename);
}


vector<uint8_t> libAES::aesGCM(vector<uint8_t>& binaryData, vector<uint8_t>& AAD, vector<uint8_t>& key, const vector<uint8_t>& iv, int enc_dec, const vector<uint8_t>& expected_tag, vector<uint8_t> counter = {0x00,0x00,0x00,0x01})
{
    libAES AES;
    vector<uint8_t> block;
    vector<uint8_t> key_saver = key;
    vector<uint8_t> nonce_counter;
    vector<uint8_t> nonce_counter_saver;
    vector<uint8_t> encNonce;
    uint32_t num;
    vector<uint8_t> H = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    vector<uint8_t> GHASH = H;
    vector<uint8_t> length_vector;

    // get lengths of data and AAD for verification
    uint64_t data_length = binaryData.size();
    uint64_t AAD_length = AAD.size();

    // Create H and verify key size
    if(key.size() == 16)      // 128 bit
        AES.aes128(H, key);
    else if(key.size() == 24) // 192 bit
        AES.aes192(H, key);
    else if(key.size() == 32) // 256 bit
        AES.aes256(H, key);
    else
        throw runtime_error("Invalid Key length");

    // create nonce and encrypt
    if(iv.size() == 12)
    {
        nonce_counter_saver = iv;
        for(int i = 0; i < 4; i ++)
            nonce_counter_saver.push_back(counter[i]);
        num = (static_cast<uint32_t>(counter[0]) << 24) | (static_cast<uint32_t>(counter[1]) << 16) | (static_cast<uint32_t>(counter[2]) << 8)  | (static_cast<uint32_t>(counter[3]));
    }
    else
    {
        nonce_counter_saver = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        // calculate padding
        vector<uint8_t> iv_padded = iv;
        while(iv_padded.size() % 16 != 0)
            iv_padded.push_back(0x00);
        for (int i = 0; i < 8; i++)
            iv_padded.push_back(0x00);

        // append length value
        uint64_t iv_bitlen = iv.size() * 8;
        for (int i = 0; i < 8; i++)
            iv_padded.push_back((iv_bitlen >> (56 - i * 8)) & 0xFF);

        // compress the nonce_counter_saver 
        for (uint64_t i = 0; i < iv_padded.size() / 16; i++) 
        {
            vector<uint8_t> block(iv_padded.begin() + (i * 16), iv_padded.begin() + (i + 1) * 16);
            AES.addRoundKey(nonce_counter_saver, block);
            nonce_counter_saver = AES.gfMult128(nonce_counter_saver, H);
        }
        num = (static_cast<uint32_t>(nonce_counter_saver[12]) << 24) | (static_cast<uint32_t>(nonce_counter_saver[13]) << 16) | (static_cast<uint32_t>(nonce_counter_saver[14]) << 8)  | (static_cast<uint32_t>(nonce_counter_saver[15]));
    }

    encNonce = nonce_counter_saver;
    key = key_saver;
    if(key.size() == 16)      // 128 bit
        AES.aes128(encNonce, key);
    else if(key.size() == 24) // 192 bit
        AES.aes192(encNonce, key);
    else                      // 256 bit
        AES.aes256(encNonce, key);

    num++;
    for (int j = 0; j < 4; j++) 
        nonce_counter_saver[12 + j] = num >> ((3 - j) * 8) & 0xFF;
    

    // Pad binary AAD with zeros for authentication
    if(AAD.size() > 0)
    {
        int AAD_padding_counter = 0;
        while(AAD.size() % 16 != 0)
        {
            AAD.insert(AAD.end(), 0x00);
            AAD_padding_counter++;
        }
        for(uint64_t i = 0; i < AAD.size() / 16; i++)
        {
            AES.addRoundKey(GHASH, vector<uint8_t>(AAD.begin() + (i * 16), AAD.begin() + (i + 1) * 16));
            GHASH = AES.gfMult128(GHASH, H);
        }
        for(int i = 0; i < AAD_padding_counter; i++)
            AAD.pop_back();
    }

    // encryption
    for(uint64_t i = 0; i < (data_length + 15) / 16; i++)
    {
        key = key_saver;
        nonce_counter = nonce_counter_saver;

        if(key.size() == 16)      // 128 bit
            AES.aes128(nonce_counter, key);
        else if(key.size() == 24) // 192 bit
            AES.aes192(nonce_counter, key);
        else                      // 256 bit
            AES.aes256(nonce_counter, key);

        if(binaryData.begin() + ((i + 1) * 16) < binaryData.end()) // check if we are on a 16 byte block or not
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
        else
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.end());
        
        if(enc_dec) // decryption
        {
            int pad_counter = 0;
            if(block.size() % 16 != 0)
            {
                while(block.size() % 16 != 0)
                {
                    block.push_back(0x00);
                    pad_counter++;
                }
            }
            
            AES.addRoundKey(GHASH, block);
            GHASH = AES.gfMult128(GHASH, H);

            for(int i = 0; i < pad_counter; i++)
                block.pop_back();
        }

        AES.addRoundKey(block, nonce_counter);
        copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
        
        if(!enc_dec) // encryption
        {
            int pad_counter = 0;
            if(block.size() % 16 != 0)
            {
                while(block.size() % 16 != 0)
                {
                    block.push_back(0x00);
                    pad_counter++;
                }
            }
            
            AES.addRoundKey(GHASH, block);
            GHASH = AES.gfMult128(GHASH, H);

            for(int i = 0; i < pad_counter; i++)
                block.pop_back();
        }

        // cumbersome increment of iv
        num++;
        for (int j = 0; j < 4; j++) 
            nonce_counter_saver[12 + j] = num >> ((3 - j) * 8) & 0xFF;
    }

    // handle length verification
    for (int i = 0; i < 8; i++)
        length_vector.push_back((AAD_length * 8) >> (56 - 8 * i));
    for (int i = 0; i < 8; i++)
        length_vector.push_back((data_length * 8) >> (56 - 8 * i));
        
    AES.addRoundKey(GHASH, length_vector);
    GHASH = AES.gfMult128(GHASH, H);
    AES.addRoundKey(GHASH, encNonce);

    if (enc_dec)
        if (GHASH != expected_tag)
            throw runtime_error("Tag mismatch: authentication failed");

    return GHASH;
}


vector<uint8_t> libAES::aesGCM(const string& filename, const string& AAD_filename, vector<uint8_t>& key, const vector<uint8_t>& iv, int enc_dec, const vector<uint8_t>& expected_tag, vector<uint8_t> counter = {0x00,0x00,0x00,0x00})
{
    libAES AES;
    vector<uint8_t> binaryData = AES.fileToBinary(filename);
    vector<uint8_t> AAD;
    try{ // AAD is not neccessary
        AAD = AES.fileToBinary(AAD_filename);}
    catch (const exception& e){}

    vector<uint8_t> block;
    vector<uint8_t> key_saver = key;
    vector<uint8_t> nonce_counter;
    vector<uint8_t> nonce_counter_saver;
    vector<uint8_t> encNonce;
    uint32_t num;
    vector<uint8_t> H = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    vector<uint8_t> GHASH = H;
    vector<uint8_t> length_vector;

    // get lengths of data and AAD for verification
    uint64_t data_length = binaryData.size();
    uint64_t AAD_length = AAD.size();

    // Create H and verify key size
    if(key.size() == 16)      // 128 bit
        AES.aes128(H, key);
    else if(key.size() == 24) // 192 bit
        AES.aes192(H, key);
    else if(key.size() == 32) // 256 bit
        AES.aes256(H, key);
    else
        throw runtime_error("Invalid Key length");

    // create nonce and encrypt
    if(iv.size() == 12)
    {
        nonce_counter_saver = iv;
        for(int i = 0; i < 4; i ++)
            nonce_counter_saver.push_back(counter[i]);
        num = (static_cast<uint32_t>(counter[0]) << 24) | (static_cast<uint32_t>(counter[1]) << 16) | (static_cast<uint32_t>(counter[2]) << 8)  | (static_cast<uint32_t>(counter[3]));
    }
    else
    {
        nonce_counter_saver = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        // calculate padding
        vector<uint8_t> iv_padded = iv;
        while(iv_padded.size() % 16 != 0)
            iv_padded.push_back(0x00);
        for (int i = 0; i < 8; i++)
            iv_padded.push_back(0x00);

        // append length value
        uint64_t iv_bitlen = iv.size() * 8;
        for (int i = 0; i < 8; i++)
            iv_padded.push_back((iv_bitlen >> (56 - i * 8)) & 0xFF);

        // compress the nonce_counter_saver 
        for (uint64_t i = 0; i < iv_padded.size() / 16; i++) 
        {
            vector<uint8_t> block(iv_padded.begin() + (i * 16), iv_padded.begin() + (i + 1) * 16);
            AES.addRoundKey(nonce_counter_saver, block);
            nonce_counter_saver = AES.gfMult128(nonce_counter_saver, H);
        }
        num = (static_cast<uint32_t>(nonce_counter_saver[12]) << 24) | (static_cast<uint32_t>(nonce_counter_saver[13]) << 16) | (static_cast<uint32_t>(nonce_counter_saver[14]) << 8)  | (static_cast<uint32_t>(nonce_counter_saver[15]));
    }

    encNonce = nonce_counter_saver;
    key = key_saver;
    if(key.size() == 16)      // 128 bit
        AES.aes128(encNonce, key);
    else if(key.size() == 24) // 192 bit
        AES.aes192(encNonce, key);
    else                      // 256 bit
        AES.aes256(encNonce, key);

    num++;
    for (int j = 0; j < 4; j++) 
        nonce_counter_saver[12 + j] = num >> ((3 - j) * 8) & 0xFF;
    

    // Pad binary AAD with zeros for authentication
    if(AAD.size() > 0)
    {
        int AAD_padding_counter = 0;
        while(AAD.size() % 16 != 0)
        {
            AAD.insert(AAD.end(), 0x00);
            AAD_padding_counter++;
        }
        for(uint64_t i = 0; i < AAD.size() / 16; i++)
        {
            AES.addRoundKey(GHASH, vector<uint8_t>(AAD.begin() + (i * 16), AAD.begin() + (i + 1) * 16));
            GHASH = AES.gfMult128(GHASH, H);
        }
        for(int i = 0; i < AAD_padding_counter; i++)
            AAD.pop_back();
    }

    // encryption
    for(uint64_t i = 0; i < (data_length + 15) / 16; i++)
    {
        key = key_saver;
        nonce_counter = nonce_counter_saver;

        if(key.size() == 16)      // 128 bit
            AES.aes128(nonce_counter, key);
        else if(key.size() == 24) // 192 bit
            AES.aes192(nonce_counter, key);
        else                      // 256 bit
            AES.aes256(nonce_counter, key);

        if(binaryData.begin() + ((i + 1) * 16) < binaryData.end()) // check if we are on a 16 byte block or not
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.begin() + ((i + 1) * 16));
        else
            block = vector<uint8_t>(binaryData.begin() + (i * 16), binaryData.end());
        
        if(enc_dec) // decryption
        {
            int pad_counter = 0;
            if(block.size() % 16 != 0)
            {
                while(block.size() % 16 != 0)
                {
                    block.push_back(0x00);
                    pad_counter++;
                }
            }
            
            AES.addRoundKey(GHASH, block);
            GHASH = AES.gfMult128(GHASH, H);

            for(int i = 0; i < pad_counter; i++)
                block.pop_back();
        }

        AES.addRoundKey(block, nonce_counter);
        copy(block.begin(), block.end(), binaryData.begin() + (i * 16));
        
        if(!enc_dec) // encryption
        {
            int pad_counter = 0;
            if(block.size() % 16 != 0)
            {
                while(block.size() % 16 != 0)
                {
                    block.push_back(0x00);
                    pad_counter++;
                }
            }
            
            AES.addRoundKey(GHASH, block);
            GHASH = AES.gfMult128(GHASH, H);

            for(int i = 0; i < pad_counter; i++)
                block.pop_back();
        }

        // cumbersome increment of iv
        num++;
        for (int j = 0; j < 4; j++) 
            nonce_counter_saver[12 + j] = num >> ((3 - j) * 8) & 0xFF;
    }

    // handle length verification
    for (int i = 0; i < 8; i++)
        length_vector.push_back((AAD_length * 8) >> (56 - 8 * i));
    for (int i = 0; i < 8; i++)
        length_vector.push_back((data_length * 8) >> (56 - 8 * i));
        
    AES.addRoundKey(GHASH, length_vector);
    GHASH = AES.gfMult128(GHASH, H);
    AES.addRoundKey(GHASH, encNonce);

    if (enc_dec)
        if (GHASH != expected_tag)
            throw runtime_error("Tag mismatch: authentication failed");

    AES.binaryToFile(binaryData, filename);      
    return GHASH;
}