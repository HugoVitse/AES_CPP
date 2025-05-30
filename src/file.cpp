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

bool File::fileExists() {
    return std::filesystem::exists(this->filePath);
}

void File::splitFile() {
    int nb_blocks = this->getFileSize() / File::BLOCK_SIZE + (this->getFileSize()%16 == 0 ? 0 : 1);
    this->partialBlock = ! (this->getFileSize()%16 == 0);
    this->blocks.resize(nb_blocks);
    std::cout << this->blocks.size() << std::endl;
}

void File::fillBlocks(){
    
    std::ifstream file(this->getFilePath());
    if( !file.is_open() ) {
        throw FileException("Impossible d'ouvrir le fichier.");
    }

    std::array<uint8_t, File::BLOCK_SIZE> flatBlock;

    for(int i = 0; i < this->blocks.size() - 1; i+=1) {
        file.seekg(i*File::BLOCK_SIZE);
        file.read(reinterpret_cast<char*>(flatBlock.data()), File::BLOCK_SIZE);

        std::array<std::array<uint8_t, File::BLOCK_DIMENSION>, File::BLOCK_DIMENSION> block;

        for (int row = 0; row < File::BLOCK_DIMENSION; ++row) {
            for (int col = 0; col < File::BLOCK_DIMENSION; ++col) {
                block[col][row] = flatBlock[row * File::BLOCK_DIMENSION + col];
            }
        }
        this->blocks[i] = block;
    }

    file.seekg( (this->blocks.size()-1) * File::BLOCK_SIZE);

    if(!this->partialBlock) {
        file.read(reinterpret_cast<char*>(flatBlock.data()), File::BLOCK_SIZE);
        std::array<std::array<uint8_t, File::BLOCK_DIMENSION>, File::BLOCK_DIMENSION> block;
        for (int row = 0; row < File::BLOCK_DIMENSION; ++row) {
            for (int col = 0; col < File::BLOCK_DIMENSION; ++col) {
                block[col][row] = flatBlock[row * File::BLOCK_DIMENSION + col];
            }
        }
        this->blocks[this->blocks.size()-1] = block;
    }

    else {
        int bytesLeft = this->getFileSize()%File::BLOCK_SIZE;
        file.read(reinterpret_cast<char*>(flatBlock.data()), bytesLeft );
        
        for(int i = bytesLeft; i < File::BLOCK_SIZE; i+=1) {
            flatBlock[i] = 0;
        }
        
        std::array<std::array<uint8_t, File::BLOCK_DIMENSION>, File::BLOCK_DIMENSION> block;
        for (int row = 0; row < File::BLOCK_DIMENSION; ++row) {
            for (int col = 0; col < File::BLOCK_DIMENSION; ++col) {
                block[col][row] = flatBlock[row * File::BLOCK_DIMENSION + col];
            }
        }
        this->blocks[this->blocks.size()-1] = block;
    }
}

}