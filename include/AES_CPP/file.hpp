#pragma once
#include <vector>
#include <string>
#include <filesystem>

namespace AES_CPP {


class File {
    public:
        File(const std::string& filePath);
        std::string getFilePath();
        bool fileExists();
        int getFileSize();
        void splitFile();
    private:
        std::string filePath;
        int fileSize;
        std::vector<std::array<uint8_t, 16>> blocks;

};

}