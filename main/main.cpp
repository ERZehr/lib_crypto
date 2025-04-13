#include <iostream>
#include <stdint.h>
#include <vector>
//#include <fstream>
//#include <iomanip>
//#include <sstream>
#include <stdexcept>
//#include <cctype>
#include "libAES.h"

using namespace std;

vector<uint8_t> fromHexString(const string& hex);

int main(int argc, char* argv[])
{
    string mode = argv[1];
    libAES AES;

    if(mode == "ECB")
    {
        if(argc != 5)
            throw("Error: Incorrect number of arguments for ECB mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        int enc_dec = stoi(argv[4]);
        AES.aesECB(filename, key, enc_dec);
    }
    else if(mode == "CBC")
    {
        if(argc != 6)
            throw("Error: Incorrect number of arguments for CBC mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        vector<uint8_t> iv = fromHexString(argv[4]);
        int enc_dec = stoi(argv[5]);
        AES.aesCBC(filename, key, iv, enc_dec);
    }
    else if(mode == "CFB")
    {
        if(argc != 6)
            throw("Error: Incorrect number of arguments for CFB mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        vector<uint8_t> iv = fromHexString(argv[4]);
        int enc_dec = stoi(argv[5]);
        AES.aesCFB(filename, key, iv, enc_dec);
    }
    else if(mode == "OFB")
    {
        if(argc != 6)
            throw("Error: Incorrect number of arguments for OFB mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        vector<uint8_t> iv = fromHexString(argv[4]);
        int enc_dec = stoi(argv[5]);
        AES.aesOFB(filename, key, iv, enc_dec);
    }
    else if(mode == "CTR")
    {
        if(argc < 5 || argc > 7)
            throw("Error: Incorrect number of arguments for CTR mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        vector<uint8_t> iv = fromHexString(argv[4]);
        int enc_dec = stoi(argv[5]);
        vector<uint8_t> counter;
        if(argc == 7)
            counter = fromHexString(argv[6]);
        else
            counter = fromHexString("00000001");
        AES.aesCTR(filename, key, iv, enc_dec, counter);
    }
    else if(mode == "GCM")
    {
        if(argc < 5 || argc > 11)
            throw("Error: Incorrect number of arguments for CTR mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        vector<uint8_t> iv = fromHexString(argv[4]);
        int enc_dec = stoi(argv[5]);
        
        vector<uint8_t> counter = {};
        vector<uint8_t> tag = {};
        string AAD = "";
        for(int i = 7; i < argc ; i+=2)
        {
            if(string(argv[i]) == "-tag")
                tag = fromHexString(argv[i + 1]);
            else if(string(argv[i]) == "-aad")
                AAD = argv[i + 1];
            else if(string(argv[i]) == "-ctr")
                counter = fromHexString(argv[i + 1]);
            else
                throw("Error: No argument " + string(argv[i]));
        }
        if(counter.empty())
            counter = fromHexString("00000001");

        AES.aesGCM(filename, AAD, key, iv, enc_dec, tag, counter);
    }
    else
        throw("No Mode " + string(argv[1]));
    return 0;
}


vector<uint8_t> fromHexString(const string& hex) {
    if (hex.length() % 2 != 0)
        throw invalid_argument("Hex string must have an even length.");

    vector<uint8_t> result;
    result.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteStr = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(stoi(byteStr, nullptr, 16));
        result.push_back(byte);
    }

    return result;
}


// int main(int argc, char* argv[])
// {
//     vector<uint8_t> key = fromHexString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
//     vector<uint8_t> Plaintext = fromHexString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
//     vector<uint8_t> AAD = fromHexString("feedfacedeadbeeffeedfacedeadbeefabaddad2");
//     vector<uint8_t> IV = fromHexString("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
//     vector<uint8_t> counter = fromHexString("00000001");
//     vector<uint8_t> expected_tag = fromHexString("");


//     cout << toHexString2(key) << endl;
//     cout << toHexString2(IV) << endl;
//     cout << toHexString2(Plaintext) << endl;
//     cout << toHexString2(AAD) << endl;
//     cout << toHexString2(counter) << endl;
//     cout << toHexString2(expected_tag) << endl;


//     libAES AES;

//     vector<uint8_t> tag = AES.aesGCM(Plaintext, AAD, key, IV, 0, expected_tag, counter);

//     cout << "Ciphertext: " << endl;
//     cout << toHexString2(Plaintext) << endl;

//     cout << "Tag: " << endl;
//     cout << toHexString2(tag) << endl;



//     return 0;
// }



// int main(int argc, char* argv[])
// {
//     vector<uint8_t> key = fromHexString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
//     vector<uint8_t> Plaintext = fromHexString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
//     vector<uint8_t> AAD = fromHexString("feedfacedeadbeeffeedfacedeadbeefabaddad2");
//     vector<uint8_t> IV = fromHexString("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
//     vector<uint8_t> counter = fromHexString("00000001");
//     vector<uint8_t> expected_tag = fromHexString("");


//     cout << toHexString2(key) << endl;
//     cout << toHexString2(IV) << endl;
//     cout << toHexString2(Plaintext) << endl;
//     cout << toHexString2(AAD) << endl;
//     cout << toHexString2(counter) << endl;
//     cout << toHexString2(expected_tag) << endl;


//     libAES AES;

//     vector<uint8_t> tag = AES.aesGCM(Plaintext, AAD, key, IV, 0, expected_tag, counter);

//     cout << "Ciphertext: " << endl;
//     cout << toHexString2(Plaintext) << endl;

//     cout << "Tag: " << endl;
//     cout << toHexString2(tag) << endl;



//     return 0;
// }