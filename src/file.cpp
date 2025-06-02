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

std::vector<Block>* File::getBlocks(){
    return &this->blocks;
}


bool File::fileExists() {
    return std::filesystem::exists(this->filePath);
}

void File::splitFile() {
    int nb_blocks = this->getFileSize() / Block::BLOCK_SIZE + (this->getFileSize()%16 == 0 ? 0 : 1);
    this->partialBlock = ! (this->getFileSize()%16 == 0);
    this->blocks.resize(nb_blocks);
}

void File::fillBlocks(Key* key, Padding* padding){
    
    
    std::ifstream file(this->getFilePath());
    if( !file.is_open() ) {
        throw FileException("Impossible d'ouvrir le fichier.");
    }

    std::array<uint8_t, Block::BLOCK_SIZE> flatBlock;

    for(int i = 0; i < this->blocks.size() - 1; i+=1) {
        file.seekg(i*Block::BLOCK_SIZE);
        file.read(reinterpret_cast<char*>(flatBlock.data()), Block::BLOCK_SIZE);

        std::array<std::array<uint8_t, Block::BLOCK_DIMENSION>, Block::BLOCK_DIMENSION> block;

        for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
            for (int row = 0; row < Block::BLOCK_DIMENSION; ++row) {
                block[col][row] = flatBlock[col * Block::BLOCK_DIMENSION + row];
            }
        }
        this->blocks[i] =  Block(block, key);
    }

    file.seekg( (this->blocks.size()-1) * Block::BLOCK_SIZE);
    
    if(padding == nullptr) {
        padding = new Padding(Padding::PKcs7);
    }

    if(!this->partialBlock) {
        file.read(reinterpret_cast<char*>(flatBlock.data()), Block::BLOCK_SIZE);
        std::array<std::array<uint8_t, Block::BLOCK_DIMENSION>, Block::BLOCK_DIMENSION> block;
        for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
            for (int row = 0; row < Block::BLOCK_DIMENSION; ++row) {
                block[col][row] = flatBlock[col * Block::BLOCK_DIMENSION + row];
            }
        }
        this->blocks[this->blocks.size()-1] = Block(block, key);

        if(*padding == Padding::PKcs7) Utils::PKcs7(&flatBlock, Block::BLOCK_SIZE);
    }

    else {
        int bytesLeft = this->getFileSize()%Block::BLOCK_SIZE;
        file.read(reinterpret_cast<char*>(flatBlock.data()), bytesLeft );

        switch(*padding) {
            case Padding::ZeroPadding:
            Utils::ZeroPadding(&flatBlock, bytesLeft);
            break;
            case Padding::PKcs7:
            Utils::PKcs7(&flatBlock, bytesLeft);
            break;
            default:
            throw FileException("Padding Inconnu");
        }
        
        
        std::array<std::array<uint8_t, Block::BLOCK_DIMENSION>, Block::BLOCK_DIMENSION> block;
        for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
            for (int row = 0; row < Block::BLOCK_DIMENSION; ++row) {
                block[col][row] = flatBlock[col * Block::BLOCK_DIMENSION + row];
            }
        }
        this->blocks[this->blocks.size()-1] = Block(block, key);
    }

    
}

void File::encodeBlocksECB(){

    for(int i=0; i < this->getBlocks()->size(); i+=1){    
        (*this->getBlocks())[i].encode();
    }

}

void File::encodeBlocksCBC(IV iv) {

    Utils::XOR( &(*this->getBlocks())[0], Block(iv.getWords()));
    (*this->getBlocks())[0].encode();

    for(int i=1; i < this->getBlocks()->size(); i+=1){   
        Utils::XOR( &(*this->getBlocks())[i], (*this->getBlocks())[i-1]);
        (*this->getBlocks())[i].encode();
    }
    
}

void File::writeBlocks(){
    std::ofstream file(this->getFilePath(), std::ios::binary);

    if (!file.is_open()) {
        throw FileException("Impossible d'ouvrir le fichier");

    }

    std::vector<uint8_t> data = {0x41, 0x42, 0x43, 0x0A}; // A, B, C, \n

    for (Block block : this->blocks) {
        for(std::array<uint8_t, Block::BLOCK_DIMENSION > column : (*block.getBlock())){
            for(uint8_t byte : column) {
                file.put(static_cast<char>(byte));
            }
        }
    }

    file.close();
}

void File::encode(Key* key, ChainingMethod Method, IV* iv) {
    
    key->splitKey();
	key->KeyExpansion();
	this->splitFile();
	this->fillBlocks(key);

    if(Method == ChainingMethod::CBC) {
        iv->splitIV();
        this->encodeBlocksCBC(*iv);
    }
    else this->encodeBlocksECB();

	this->writeBlocks();
}


}