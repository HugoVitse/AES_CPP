#include "AES_CPP/file.hpp"
#include "AES_CPP/fileException.hpp"

namespace AES_CPP {

    
File::File(const std::string& filePath) : filePath(filePath) {
    if(!this->fileExists()) {
        throw FileException("Le fichier n'existe pas");
    }
    else {
        this->fileSize = std::filesystem::file_size(this->filePath);
    }
}

std::string File::getFilePath() {
    return this->filePath;
}

int File::getFileSize() {
    return this->fileSize;
}

bool File::fileExists(){
    return std::filesystem::exists(this->filePath);
}

}