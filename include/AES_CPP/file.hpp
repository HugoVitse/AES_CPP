#pragma once
#include "AES_CPP/block.hpp"
#include "AES_CPP/iv.hpp"
#include "AES_CPP/utils.hpp"
#include <vector>
#include <string>
#include <filesystem>
#include <array>
#include <fstream>
#include <iostream>

namespace AES_CPP {
    
enum class ChainingMethod {
    CBC,
    EBC
};

enum class Padding {
    ZeroPadding,
    PKcs7
};


class File {
    public:
        File(const std::string& filePath);
        std::string getFilePath();
        bool fileExists();
        int getFileSize();
        std::vector<Block>* getBlocks();
        void splitFile();
        void fillBlocks(Key* key, Padding* padding = nullptr);
        void encodeBlocksECB();
        void encodeBlocksCBC(IV iv);
        void writeBlocks();
        void encode(Key* key, ChainingMethod Method, IV* iv=nullptr);

    private:
        std::string filePath;
        int fileSize;
        std::vector<Block> blocks;
        bool partialBlock;

};


}