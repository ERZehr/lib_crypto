#include <iostream>
#include <stdint.h>
#include <vector>
#include <iomanip>
#include <sstream>
#include "libAES.h"

using namespace std;

int main(int argc, char* argv[])
{
    vector<uint8_t> block = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    vector<uint8_t> key = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    vector<uint8_t> Gn = {0x00,0x00,0x00,0x01};

    libAES AES;


    for(int i = 0; i < 16; i++)
    {
        stringstream ss;
        ss << hex << setw(2) << setfill('0') << (int)block[i];
        string hexStr = ss.str();
        cout << hexStr << " ";
    }
    cout << endl;
    
    AES.addRoundKey(block, key);

    for(int i = 1; i < 10; i++)
    {
        AES.sBox(block);
        AES.shiftRows(block);
        AES.mixColumns(block);
        Gn = AES.calcRoundKey128(key, Gn, i);
        AES.addRoundKey(block, key);
    }

    AES.sBox(block);
    AES.shiftRows(block);
    Gn = AES.calcRoundKey128(key, Gn, 10);
    AES.addRoundKey(block, key);

    for(int i = 0; i < 16; i++)
    {
        stringstream ss;
        ss << hex << setw(2) << setfill('0') << (int)block[i];
        string hexStr = ss.str();
        cout << hexStr << " ";
    }
    cout << endl;

    return 0;
}


