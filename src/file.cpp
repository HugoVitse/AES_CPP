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

Block* File::getTag(){
    return this->tag;
}


std::string File::getOutputFilePath() {
    return this->outputFilePath;
}


long File::getFileSize() {
    return this->fileSize;
}

void File::setFileSize(long size){
    this->fileSize = size;
}

std::vector<Block>* File::getBlocks(){
    return &this->blocks;
}


bool File::fileExists() {
    return std::filesystem::exists(this->filePath);
}

void File::splitFile(Padding* padding) {

    if(*padding == Padding::None){
        this->fileSize -= 34;
    }

    int nb_blocks = ( this->fileSize / Block::BLOCK_SIZE ) + 
                    ((this->fileSize % Block::BLOCK_SIZE == 0 && *padding != Padding::PKcs7)  ?  0 : 1);

    this->nbFlows = ( this->fileSize  /  File::FILE_SIZE_MAX ) + 
                    ((this->fileSize  %  File::FILE_SIZE_MAX == 0 ) ? 0 : 1);

    this->partialBlock = ! ( this->fileSize % Block::BLOCK_SIZE == 0 );

    this->blocks.resize( this->nbFlows == 1 ? nb_blocks : File::FILE_SIZE_MAX / Block::BLOCK_SIZE) ;
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
        int i = Block::BLOCK_DIMENSION-1;
        int j = Block::BLOCK_DIMENSION-1;
        while( (*this->blocks[this->blocks.size()-1].getBlock())[i][j] == 0 ){

            j-=1;
            if( j == -1 ) {
                i -= 1;
                j = Block::BLOCK_DIMENSION-1;
            }

        }
        return i*Block::BLOCK_DIMENSION + j + 1;
    }

    else {
        return Block::BLOCK_SIZE - lastByte;
    }
}

void File::calculateTag(Key* key, IV iv, int* bytesLeft) {

    std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> zeros;
    for (auto& row : zeros) {
        row.fill(0);
    }

    Block zerosBlock(zeros, key);
    zerosBlock.encode();

    
    this->tag->toString();


    Utils::blockMultiplication(tag, zerosBlock);

    for(auto block : *this->getBlocks()) {
        Utils::XOR(tag, block);
        Utils::blockMultiplication(tag, zerosBlock);
    }

    this->tag->toString();


    std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> len;
    for (auto& row : len) {
        row.fill(0);
    }

    int pow16 = 1;
    int actualSize = bytesLeft == nullptr ? this->getFileSize() : (this->getFileSize() - (Block::BLOCK_SIZE - *bytesLeft));
    int tmp = actualSize* 8;
    while( pow(16,pow16) < (actualSize*8) ){
        pow16+=1;
    }

    pow16 -=1;
    for(int p = pow16; p >= 0; p-=1){
        len[  (15-p )/ Block::BLOCK_DIMENSION ][  (15-p)%Block::BLOCK_DIMENSION  ] = tmp / pow(16,pow16);
        tmp -= (tmp / pow(16,pow16)) *  pow(16,pow16);
    }

    Block lenBlock(len);
    lenBlock.toString();

    Utils::XOR(tag, lenBlock);
    this->tag->toString();
    Utils::blockMultiplication(tag, zerosBlock);
    this->tag->toString();

    iv.getIV()[iv.getSize()-1] = 0;
    iv.splitIV();

    Block counterBlock(iv.getWords(), key);

    Utils::XOR(tag, counterBlock);

    this->tag->toString();

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


void File::encodeBlocksCTR(IV iv, Key* key, bool GCM) {
    auto blocks = this->getBlocks();
    size_t total_blocks = blocks->size();
    size_t num_threads = std::min(total_blocks, size_t(std::thread::hardware_concurrency()));

    std::vector<std::thread> threads;

    
    
    
    for (size_t t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            for (size_t i = t; i < total_blocks; i += num_threads) {

                int pow16 = 1;
                int tmp = i + (int)GCM;
                while( pow(16,pow16) < i ){
                    pow16+=1;
                }

                pow16 -=1;
                for(int p = pow16; p >= 0; p-=1){
                    iv.getIV()[15-p] = tmp / pow(16,pow16);
                    tmp -= (tmp / pow(16,pow16)) *  pow(16,pow16);
                }                
                iv.splitIV();
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


void File::encodeBlocksGCM(IV iv, Key* key) {
    
    this->encodeBlocksCTR(iv,key,true);
    this->calculateTag(key,iv);
        
}

void File::decodeBlocksGCM(IV iv, Key* key, int bytesLeft) {
    this->calculateTag(key,iv, &bytesLeft);
    this->decodeBlocksCTR(iv, key);
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

void File::writeData(int bytesLeft, ChainingMethod Method,  IV* iv, Block* tag){
    std::fstream file(this->getOutputFilePath(), std::ios::in | std::ios::out | std::ios::binary);


    if (!file.is_open()) {
        file.open(this->getOutputFilePath(), std::ios::out | std::ios::binary);
        file.close();
        file.open(this->getOutputFilePath(), std::ios::in | std::ios::out | std::ios::binary);
    }



    file.seekp(0, std::ios::end);
    file.put(static_cast<char>(bytesLeft));
    file.put(static_cast<char>(Method));

    if(iv == nullptr) {
        for(int i = 0; i < 16; i+=1){
            file.put(static_cast<char>(0));
        }
    }

    else {
        for(auto byte : iv->getIV()){
            file.put(byte);
        }
    }

    if(tag == nullptr) {
        for(int i = 0; i < 16; i+=1){
            file.put(static_cast<char>(0));
        }
    }

    else {
        for(auto col : (*tag->getBlock())){
            for(auto row : col){
                file.put(static_cast<char>(row));
            }
        }
    }

    file.close();

}

Data File::readData() {

    IV* iv = nullptr;
    Block* tag = nullptr;

    std::ifstream file(this->getFilePath());
    if( !file.is_open() ) {
        throw FileException("Impossible d'ouvrir le fichier.");
    }

    file.seekg(-34, std::ios::end);
    char byte;
    file.read(&byte, 1);

    int bytesLeft = (int)byte;
    file.seekg(-33, std::ios::end);
    file.read(&byte, 1);

    ChainingMethod method = static_cast<ChainingMethod>((int)byte);

    if(method != ChainingMethod::ECB) {
        file.seekg(-32, std::ios::end);
        std::vector<uint8_t> _iv(16);
        file.read(reinterpret_cast<char*>(_iv.data()), 16);
        iv = new IV(_iv);
    }

    if(method == ChainingMethod::GCM) {
        char byte2;

        std::array<std::array<uint8_t, Block::BLOCK_DIMENSION>, Block::BLOCK_DIMENSION> _tag2D;
        for (size_t i = 0; i < 4; ++i) {
            for (size_t j = 0; j < 4; ++j) {
                file.seekg(-16 + (i*Block::BLOCK_DIMENSION + j), std::ios::end);
                file.read(&byte2, 1);
                _tag2D[i][j] = static_cast<uint8_t>(byte2);
            }
        }
        tag = new Block(_tag2D);

    }

    Data test(method, iv, tag, bytesLeft);
    return test;



}


void File::encode(Key* key, ChainingMethod Method,  IV* iv, Padding* padding, bool deprecated) {

    
    int bytesLeft = this->getFileSize()%Block::BLOCK_SIZE;
    key->splitKey();
	key->KeyExpansion();
	this->splitFile(padding);

    std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> AAD;
    for (auto& row : AAD) {
        row.fill(0);
    }

    this->tag = new Block(AAD, key);



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
            case ChainingMethod::GCM:
            iv->splitIV();
            this->encodeBlocksGCM(*iv, key);
            break;
            
        }
        
        this->writeBlocks(i); //85341 first good is 
        
        
    }
    if(Method == ChainingMethod::GCM){
        std::cout << std::endl << "Tag : ";
        this->tag->toString();
        this->writeData(bytesLeft,Method,iv,tag);
    } 
    else {
        this->writeData(bytesLeft,Method,iv,nullptr);
    }
    
}

void File::decode(Key* key, bool deprecated) {
    
    key->splitKey();
	key->KeyExpansion();
	this->splitFile(new Padding(Padding::None));

    Data data = this->readData();
    std::filesystem::resize_file(this->getFilePath(), this->getFileSize());

    ChainingMethod Method = data.getMethod();
    IV* iv = data.getIV();

    std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> AAD;
    for (auto& row : AAD) {
        row.fill(0);
    }

    this->tag = new Block(AAD, key);

    

    
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
            case ChainingMethod::GCM:
            iv->splitIV();
            this->decodeBlocksGCM(*iv, key, data.getBytesLeft());
            break;
        }


        if(i == this->nbFlows - 1) {
            int dePad = this->dePad();
            this->writeBlocks(i, dePad );
            std::filesystem::resize_file(this->getFilePath(), ( this->getFileSize() - (Block::BLOCK_SIZE - dePad))  );

        }
        else this->writeBlocks(i);

    }

    if(Method == ChainingMethod::GCM){
        std::cout << std::endl << "Tag : ";
        this->tag->toString();

        data.getTag()->toString();
        if( *this->tag != *data.getTag()) {
            throw FileException("Tag incorrect ! L'intégrité des données a peut être été altérée");
        }
    }
    
}


Data::Data(ChainingMethod Method,IV* iv, Block* tag, int bytesLeft) {
    this->Method = Method;
    this->bytesLeft = bytesLeft;
    this->iv = iv;
    this->tag = tag;
}

ChainingMethod Data::getMethod() {
    return this->Method;
}

IV* Data::getIV(){
    return this->iv;
}

Block* Data::getTag(){
    return this->tag;
}

int Data::getBytesLeft() {
    return this->bytesLeft;
}

}