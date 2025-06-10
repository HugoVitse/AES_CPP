#include "AES_CPP/file.hpp"
#include "AES_CPP/fileException.hpp"
#include <math.h>

namespace AES_CPP {

    
File::File(const std::string& filePath, const std::string& outputFilePath) : filePath(filePath), outputFilePath(outputFilePath) {
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

std::string File::getOutputFilePath() {
    return this->outputFilePath;
}


long File::getFileSize() {
    return this->fileSize;
}

std::vector<Block>* File::getBlocks(){
    return &this->blocks;
}


bool File::fileExists() {
    return std::filesystem::exists(this->filePath);
}

void File::splitFile(Padding* padding) {
    int nb_blocks = (this->getFileSize() / Block::BLOCK_SIZE) + (  (this->getFileSize()%Block::BLOCK_SIZE == 0 && *padding != Padding::PKcs7)   ? 0 : 1);
    this->nbFlows = this->getFileSize() / File::FILE_SIZE_MAX + (this->getFileSize()%File::FILE_SIZE_MAX == 0 ? 0 : 1);

    this->partialBlock = ! (this->getFileSize()%16 == 0);
    this->blocks.resize(this->nbFlows == 1 ? nb_blocks : File::FILE_SIZE_MAX / Block::BLOCK_SIZE);
    this->sizeLastFlow = nb_blocks % File::FLOW_SIZE;

}

void File::fillBlocks(Key* key, int flow){
    
    
    std::ifstream file(this->getFilePath());
    if( !file.is_open() ) {
        throw FileException("Impossible d'ouvrir le fichier.");
    }

    std::array<uint8_t, Block::BLOCK_SIZE> flatBlock;

    for(int i = 0; i < this->blocks.size() -  (flow == (this->nbFlows-1) ? 1 : 0); i+=1) {
        file.seekg(flow*File::FILE_SIZE_MAX + i*Block::BLOCK_SIZE);
        file.read(reinterpret_cast<char*>(flatBlock.data()), Block::BLOCK_SIZE);

         
        std::array<std::array<uint8_t, Block::BLOCK_DIMENSION>, Block::BLOCK_DIMENSION> block;

        for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
            for (int row = 0; row < Block::BLOCK_DIMENSION; ++row) {
                block[col][row] = flatBlock[col * Block::BLOCK_DIMENSION + row];
            }
        }
        this->blocks[i] =  Block(block, key);
    }

    
    
}

void File::fillLastBlock(Key* key, int flow, Padding* padding){

    std::ifstream file(this->getFilePath());
    if( !file.is_open() ) {
        throw FileException("Impossible d'ouvrir le fichier.");
    }

    std::array<uint8_t, Block::BLOCK_SIZE> flatBlock;

    
    file.seekg(flow*File::FILE_SIZE_MAX + (this->blocks.size()-1) * Block::BLOCK_SIZE);
    
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
            case Padding::None:
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


uint8_t File::dePad() {
    uint8_t lastByte = (*this->blocks[this->blocks.size()-1].getBlock())[Block::BLOCK_DIMENSION-1][Block::BLOCK_DIMENSION-1];

    if(lastByte == 0) {
        int i = Block::BLOCK_DIMENSION;
        int j = Block::BLOCK_DIMENSION;
        while( (*this->blocks[this->blocks.size()-1].getBlock())[i][j] == 0 ){
            j-=1;
            if( j == 0 ) {
                i -= 1;
                j = Block::BLOCK_DIMENSION;
            }
        }
        return i*Block::BLOCK_DIMENSION + j + 1;
    }

    else {
        return Block::BLOCK_SIZE - lastByte;
    }
}

void File::encodeBloc(Block* bloc) {
    bloc->encode();
}

void File::decodeBloc(Block* bloc) {
    bloc->decode();
}

void File::encodeBlocksECB(){

    auto blocks = this->getBlocks();
    size_t total_blocks = blocks->size();
    size_t num_threads = std::min(total_blocks, size_t(std::thread::hardware_concurrency()));

    std::vector<std::thread> threads;

    for (size_t t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            for (size_t i = t; i < total_blocks; i += num_threads) {
                File::encodeBloc(&(*blocks)[i]);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

}

void File::decodeBlocksECB(){

    auto blocks = this->getBlocks();
    size_t total_blocks = blocks->size();
    size_t num_threads = std::min(total_blocks, size_t(std::thread::hardware_concurrency()));

    std::vector<std::thread> threads;

    for (size_t t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            for (size_t i = t; i < total_blocks; i += num_threads) {
                File::decodeBloc(&(*blocks)[i]);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

}


void File::encodeBlocksCTR(IV iv, Key* key) {
    auto blocks = this->getBlocks();
    size_t total_blocks = blocks->size();
    size_t num_threads = std::min(total_blocks, size_t(std::thread::hardware_concurrency()));

    std::vector<std::thread> threads;

    
    
    
    for (size_t t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            for (size_t i = t; i < total_blocks; i += num_threads) {

                int pow16 = 1;
                int tmp = i;
                while( pow(16,pow16) < i ){
                    pow16+=1;
                }

                pow16 -=1;
                for(int p = pow16; p >= 0; p-=1){
                    iv.getIV()[15-p] = tmp / pow(16,pow16);
                    tmp -= (tmp / pow(16,pow16)) *  pow(16,pow16);
                }                
                
                Block* counterBlock = new Block(iv.getWords(), key);

                File::encodeBloc(counterBlock);
                Utils::XOR(&(*blocks)[i], *counterBlock);

                
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }
}

void File::decodeBlocksCTR(IV iv, Key* key){

    this->encodeBlocksCTR(iv,key);

}

//deprecated por test purposes only
void File::deprecatedEncodeBlocksECB(){
    for(int i=0; i < this->getBlocks()->size(); i+=1){    
        (*this->getBlocks())[i].encode();
    }

}


void File::deprecatedDecodeBlocksECB() {
    for(int i=0; i < this->getBlocks()->size(); i+=1){    
        (*this->getBlocks())[i].decode();
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

void File::decodeBlocksCBC(IV iv) {

    for(int i= this->getBlocks()->size() - 1; i > 0; i-=1){   
        (*this->getBlocks())[i].decode();
        Utils::XOR( &(*this->getBlocks())[i], (*this->getBlocks())[i-1]);
    }

    (*this->getBlocks())[0].decode();
    Utils::XOR( &(*this->getBlocks())[0], Block(iv.getWords()));
    
}

void File::writeBlocks(int flow, int fin){
    std::fstream file(this->getOutputFilePath(), std::ios::in | std::ios::out | std::ios::binary);


    if (!file.is_open()) {
        file.open(this->getOutputFilePath(), std::ios::out | std::ios::binary);
        file.close();
        file.open(this->getOutputFilePath(), std::ios::in | std::ios::out | std::ios::binary);
    }



    file.seekp(flow * File::FILE_SIZE_MAX);


    int end = Block::BLOCK_SIZE;

    for(int k = 0; k < this->blocks.size(); k+=1) {

        if(k == this->blocks.size() - 1 ) {
            end = fin;
        }
        

        Block block = (*this->getBlocks())[k];
        


        for(int i = 0; i < end ; i+=1){
            file.put(static_cast<char>(  (*block.getBlock())[i/Block::BLOCK_DIMENSION][i%Block::BLOCK_DIMENSION]  ));
        }


    }

    file.close();
}

void File::encode(Key* key, ChainingMethod Method,  IV* iv, Padding* padding, bool deprecated) {
    
    key->splitKey();
	key->KeyExpansion();
	this->splitFile(padding);



    for(int i = 0; i < this->nbFlows; i+=1){
        Utils::showProgressBar(i, this->nbFlows-1);

        if(i == this->nbFlows - 1) {
            this->blocks.resize(this->sizeLastFlow);
            this->fillBlocks(key, i);
            this->fillLastBlock(key,i, padding);
        }
        else {
            this->fillBlocks(key, i);
        }

        switch(Method) {
            case ChainingMethod::CBC:
            iv->splitIV();
            this->encodeBlocksCBC(*iv);
            break;
            case ChainingMethod::ECB:
            deprecated ? this->deprecatedEncodeBlocksECB() : this->encodeBlocksECB();
            break;
            case ChainingMethod::CTR:
            iv->splitIV();
            this->encodeBlocksCTR(*iv, key);
            break;

        }
        
        this->writeBlocks(i); //85341 first good is 


    }
    
}

void File::decode(Key* key, ChainingMethod Method, IV* iv, bool deprecated) {
    
    key->splitKey();
	key->KeyExpansion();
	this->splitFile(new Padding(Padding::None));

    

    
    for(int i = 0; i < this->nbFlows; i+=1){

        Utils::showProgressBar(i, this->nbFlows-1);


        if(i == this->nbFlows - 1) {
            this->blocks.resize(this->sizeLastFlow);
            this->fillBlocks(key, i);
            this->fillLastBlock(key,i, new Padding(Padding::None));
        }
        else {
            this->fillBlocks(key, i);
        }


        switch(Method) {
            case ChainingMethod::CBC:
            iv->splitIV();
            this->decodeBlocksCBC(*iv);
            break;
            case ChainingMethod::ECB:
            deprecated ? this->deprecatedDecodeBlocksECB() : decodeBlocksECB();
            break;
            case ChainingMethod::CTR:
            iv->splitIV();
            this->decodeBlocksCTR(*iv, key);
            break;
        }


        if(i == this->nbFlows - 1) {
            int dePad = this->dePad();
            this->writeBlocks(i, dePad );
            std::filesystem::resize_file(this->getFilePath(), (this->getFileSize() - (Block::BLOCK_SIZE - dePad))  );

        }
        else this->writeBlocks(i);

    }
    


    
}

}