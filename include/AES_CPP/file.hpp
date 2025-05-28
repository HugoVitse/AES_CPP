#pragma once
#include <vector>
#include <string>
#include <filesystem>
#include <array>
#include <fstream>
#include <iostream>

namespace AES_CPP {


class File {
    public:
        File(const std::string& filePath);
        std::string getFilePath();
        bool fileExists();
        int getFileSize();
        void splitFile();
        void fillBlocks();

        static const int BLOCK_DIMENSION = 4;
        static const int BLOCK_SIZE = 16;
    private:
        std::string filePath;
        int fileSize;
        std::vector< std::array< std::array< uint8_t, File::BLOCK_DIMENSION >, File::BLOCK_DIMENSION> > blocks;
        bool partialBlock;

};

}