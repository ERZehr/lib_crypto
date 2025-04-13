#include <iostream>
#include <stdint.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include "libAES.h"

using namespace std;

vector<uint8_t> fromHexString(const string& hex);
string vectorToHex(const vector<uint8_t>& data);
void writeStringToFile(const std::string& filename, const string& content);


int main(int argc, char* argv[])
{
    string mode = argv[1];
    libAES AES;

    if(mode == "ECB")
    {
        if(argc != 5)
            throw runtime_error("Error: Incorrect number of arguments for ECB mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        int enc_dec = stoi(argv[4]);
        AES.aesECB(filename, key, enc_dec);
    }
    else if(mode == "CBC")
    {
        if(argc != 6)
            throw runtime_error("Error: Incorrect number of arguments for CBC mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        vector<uint8_t> iv = fromHexString(argv[4]);
        int enc_dec = stoi(argv[5]);
        AES.aesCBC(filename, key, iv, enc_dec);
    }
    else if(mode == "CFB")
    {
        if(argc != 6)
            throw runtime_error("Error: Incorrect number of arguments for CFB mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        vector<uint8_t> iv = fromHexString(argv[4]);
        int enc_dec = stoi(argv[5]);
        AES.aesCFB(filename, key, iv, enc_dec);
    }
    else if(mode == "OFB")
    {
        if(argc != 6)
            throw runtime_error("Error: Incorrect number of arguments for OFB mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        vector<uint8_t> iv = fromHexString(argv[4]);
        int enc_dec = stoi(argv[5]);
        AES.aesOFB(filename, key, iv, enc_dec);
    }
    else if(mode == "CTR")
    {
        if(argc < 5 || argc > 7)
            throw runtime_error("Error: Incorrect number of arguments for CTR mode");
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
        if(argc < 5 || argc > 12)
            throw runtime_error("Error: Incorrect number of arguments for GCM mode");
        string filename = argv[2];
        vector<uint8_t> key = fromHexString(argv[3]);
        vector<uint8_t> iv = fromHexString(argv[4]);
        int enc_dec = stoi(argv[5]);
        
        vector<uint8_t> counter = {};
        vector<uint8_t> tag = {};
        string AAD = "";
        for(int i = 6; i < argc ; i+=2)
        {
            if(string(argv[i]) == "-tag")
                tag = fromHexString(argv[i + 1]);
            else if(string(argv[i]) == "-aad")
                AAD = argv[i + 1];
            else if(string(argv[i]) == "-ctr")
                counter = fromHexString(argv[i + 1]);
            else
                throw runtime_error("Error: No argument " + string(argv[i]));
        }
        if(counter.empty())
            counter = fromHexString("00000001");

        tag = AES.aesGCM(filename, AAD, key, iv, enc_dec, tag, counter);
        writeStringToFile("tag", vectorToHex(tag));
    }
    else
        throw runtime_error("No Mode " + string(argv[1]));
    return 0;
}


vector<uint8_t> fromHexString(const string& hex) 
{
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

string vectorToHex(const vector<uint8_t>& data) 
{
    ostringstream oss;
    oss << hex << std::setfill('0');

    for (uint8_t byte : data) {
        oss << setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

void writeStringToFile(const std::string& filename, const string& content) 
{
    ofstream file(filename);

    if (!file)
        throw runtime_error("Error: Could not open file for writing: ");

    file << content;
    file.close();
}