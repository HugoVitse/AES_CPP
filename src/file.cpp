#include "AES_CPP/file.hpp"
#include "AES_CPP/fileException.hpp"
#include <math.h>
#include <algorithm>  // Pour std::copy

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

    this->nbFlows = ( nb_blocks  /  File::FLOW_SIZE ) + 
                    (( nb_blocks  %  File::FLOW_SIZE == 0 ) ? 0 : 1);

    this->partialBlock = ! ( this->fileSize % Block::BLOCK_SIZE == 0 );

    this->blocks.resize( this->nbFlows == 1 ? nb_blocks : File::FILE_SIZE_MAX / Block::BLOCK_SIZE) ;
    this->sizeLastFlow = nb_blocks % File::FLOW_SIZE;
    this->nbblocks = nb_blocks;

}

void File::fillBlocks(Key* key, int flow){
    
    std::ifstream file(this->getFilePath(), std::ios::binary);
    if( !file.is_open() ) {
        throw FileException("Impossible d'ouvrir le fichier.");
    }

    // Calculer la taille à lire pour ce flow
    size_t flowOffset = flow * File::FILE_SIZE_MAX;
    size_t blocksToRead = this->blocks.size() - (flow == (this->nbFlows-1) ? 1 : 0);
    size_t bytesToRead = blocksToRead * Block::BLOCK_SIZE;
    
    // Allouer un buffer pour lire tout le chunk en une seule fois
    std::vector<uint8_t> chunkBuffer(bytesToRead);
    
    // Lecture unique du chunk complet (OPTIMISATION MAJEURE)
    file.seekg(flowOffset);
    file.read(reinterpret_cast<char*>(chunkBuffer.data()), bytesToRead);
    
    if (!file && !file.eof()) {
        throw FileException("Erreur lors de la lecture du fichier.");
    }
    
    file.close();
    
    // Maintenant, découper le buffer en blocs (opération en mémoire, très rapide)
    std::array<uint8_t, Block::BLOCK_SIZE> flatBlock;
    
    for(size_t i = 0; i < blocksToRead; i++) {
        // Copier 16 octets du buffer vers flatBlock
        std::copy(
            chunkBuffer.begin() + (i * Block::BLOCK_SIZE),
            chunkBuffer.begin() + ((i + 1) * Block::BLOCK_SIZE),
            flatBlock.begin()
        );
        
        // Transformer en matrice 2D
        std::array<std::array<uint8_t, Block::BLOCK_DIMENSION>, Block::BLOCK_DIMENSION> block;
        for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
            for (int row = 0; row < Block::BLOCK_DIMENSION; ++row) {
                block[col][row] = flatBlock[col * Block::BLOCK_DIMENSION + row];
            }
        }
        
        this->blocks[i] = Block(block, key);
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

        if(*padding == Padding::None){

            file.read(reinterpret_cast<char*>(flatBlock.data()), Block::BLOCK_SIZE);
            std::array<std::array<uint8_t, Block::BLOCK_DIMENSION>, Block::BLOCK_DIMENSION> block;
            for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
                for (int row = 0; row < Block::BLOCK_DIMENSION; ++row) {
                    block[col][row] = flatBlock[col * Block::BLOCK_DIMENSION + row];
                }
            }
            this->blocks[this->blocks.size()-1] = Block(block, key);
        }

        if(*padding == Padding::PKcs7){
     
            std::array<uint8_t, Block::BLOCK_SIZE> flatBlock2;
            std::array<std::array<uint8_t, Block::BLOCK_DIMENSION>, Block::BLOCK_DIMENSION> block2;

            Utils::PKcs7(&flatBlock2, 0);
            for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
                for (int row = 0; row < Block::BLOCK_DIMENSION; ++row) {
                    block2[col][row] = flatBlock2[col * Block::BLOCK_DIMENSION + row];
                }
            }

            this->blocks[this->blocks.size()-1] = Block(block2, key);
        }
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


    Utils::blockMultiplication(tag, zerosBlock);

    for(auto block : *this->getBlocks()) {
        Utils::XOR(tag, block);
        Utils::blockMultiplication(tag, zerosBlock);
    }


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

    Utils::XOR(tag, lenBlock);
    Utils::blockMultiplication(tag, zerosBlock);

    iv.getIV()[iv.getSize()-1] = 0;
    iv.splitIV();

    Block counterBlock(iv.getWords(), key);
    counterBlock.encode();

    Utils::XOR(tag, counterBlock);

    


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


void File::encodeBlocksCTR(IV iv, Key* key, int flow, bool GCM) {
    auto blocks = this->getBlocks();
    size_t total_blocks = blocks->size();
    size_t num_threads = std::min(total_blocks, size_t(std::thread::hardware_concurrency()));

    std::vector<std::thread> threads;


    for (size_t t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            IV baseIV = iv;
            baseIV.splitIV();

            for (size_t i = t; i < total_blocks; i += num_threads) {
                size_t increment = flow * File::FLOW_SIZE + i + (GCM ? 1 : 0);

                IV localIV = baseIV;
                Utils::add_to_iv_be(localIV, increment);

                Block counterBlock(localIV.getWords(), key);
                File::encodeBloc(&counterBlock);
                Utils::XOR(&(*blocks)[i], counterBlock);
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // for (size_t i = 0; i < total_blocks; i += 1) {

    //     // Créer une copie de l'IV pour ce bloc
    //     std::vector<uint8_t> ivCopy = iv.getIV();  // Copie explicite du vecteur
    //     IV localIV(ivCopy);
    //     localIV.splitIV();
        
    //     // Ajouter directement l'offset à l'IV (beaucoup plus rapide qu'une boucle)
    //     size_t increment = flow*File::FLOW_SIZE +  i + (GCM ? 1 : 0);
    //     Utils::add_to_iv_be(localIV, increment);

    //     Block* counterBlock = new Block(localIV.getWords(), key);
    //     File::encodeBloc(counterBlock);
    //     Utils::XOR(&(*blocks)[i], *counterBlock);
        
    //     delete counterBlock;
    // }
}


void File::decodeBlocksCTR(IV iv, Key* key, int flow, bool GCM){
    this->encodeBlocksCTR(iv,key, flow, GCM);

}


void File::encodeBlocksGCM(IV iv, int flow, Key* key) {
    
    this->encodeBlocksCTR(iv,key, flow, true);
    this->calculateTag(key,iv);
        
}

void File::decodeBlocksGCM(IV iv, Key* key, int flow, int bytesLeft) {
    this->decodeBlocksCTR(iv, key, flow, true);
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

    size_t totalBytes = (this->blocks.size() - 1) * Block::BLOCK_SIZE + fin;
    
    std::vector<uint8_t> chunkBuffer;
    chunkBuffer.reserve(totalBytes);
    
    for(size_t k = 0; k < this->blocks.size(); k++) {
        Block block = (*this->getBlocks())[k];
        int bytesToWrite = (k == this->blocks.size() - 1) ? fin : Block::BLOCK_SIZE;
        
        for(int i = 0; i < bytesToWrite; i++) {
            chunkBuffer.push_back(
                (*block.getBlock())[i / Block::BLOCK_DIMENSION][i % Block::BLOCK_DIMENSION]
            );
        }
    }
    
    file.seekp(flow * File::FILE_SIZE_MAX);
    file.write(reinterpret_cast<const char*>(chunkBuffer.data()), chunkBuffer.size());
    
    if (!file) {
        throw FileException("Erreur lors de l'écriture du fichier.");
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

IV* File::readIV(bool input) {


    std::ifstream file( input ? this->getFilePath() : this->getOutputFilePath(), std::ios::binary);
    if (!file.is_open()) {
        throw FileException("Impossible d'ouvrir le fichier.");
    }

    file.seekg(0, std::ios::end);
    std::streamoff size = file.tellg();
    if (size < 16) {
        throw FileException("Fichier trop petit pour contenir un IV.");
    }

    file.seekg(-16, std::ios::end);
    std::vector<uint8_t> _iv(16);
    file.read(reinterpret_cast<char*>(_iv.data()), 16);
    if (!file) {
        throw FileException("Impossible de lire l'IV.");
    }

    return new IV(_iv);
}

IV* File::readIV(int flow) {

    std::ifstream file(this->getFilePath(), std::ios::binary);
    if (!file.is_open()) {
        throw FileException("Impossible d'ouvrir le fichier.");
    }
   
    file.seekg( ( flow * File::FILE_SIZE_MAX ) - Block::BLOCK_SIZE, std::ios::beg);
    std::streamoff size = file.tellg();
    if (size < 16) {
        throw FileException("Fichier trop petit pour contenir un IV.");
    }

    file.seekg( ( flow * File::FILE_SIZE_MAX ) - Block::BLOCK_SIZE, std::ios::beg);
    std::vector<uint8_t> _iv(16);
    file.read(reinterpret_cast<char*>(_iv.data()), 16);
    if (!file) {
        throw FileException("Impossible de lire l'IV.");
    }
    return new IV(_iv);
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


void File::encode(Key* key, ChainingMethod Method,  IV* iv, Padding* padding, bool deprecated, bool metaData) {


    Utils::setUseClassicTTables(true);

    int bytesLeft = this->getFileSize()%Block::BLOCK_SIZE;
    key->splitKey();
	key->KeyExpansion();
	this->splitFile(padding);

    std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> AAD;
    for (auto& row : AAD) {
        row.fill(0);
    }

    this->tag = new Block(AAD, key);
    IV* localIV = iv;

    for(int i = 0; i < this->nbFlows; i+=1){

        Utils::showProgressBar(i, this->nbFlows-1);

        if(i == this->nbFlows - 1) {
            // Si sizeLastFlow == 0, cela signifie que le dernier flow est complet
            if(this->sizeLastFlow == 0) {
                // Traiter comme un flow complet
                this->fillBlocks(key, i);
            } else {
                // Traiter comme un flow partiel
                this->blocks.resize(this->sizeLastFlow);
                this->fillBlocks(key, i);
                this->fillLastBlock(key,i, padding);
            }
        }
        else {
            this->fillBlocks(key, i);
        }

        if(i != 0 && Method == ChainingMethod::CBC) {
            localIV = this->readIV();
        }


        switch(Method) {
            case ChainingMethod::CBC:
            localIV->splitIV();
            this->encodeBlocksCBC(*localIV);
            break;
            case ChainingMethod::ECB:
            deprecated ? this->deprecatedEncodeBlocksECB() : this->encodeBlocksECB();
            break;
            case ChainingMethod::CTR:
            this->encodeBlocksCTR(*iv, key, i);
            break;
            case ChainingMethod::GCM:
            this->encodeBlocksGCM(*iv, i, key);
            break;
            
        }
        
        this->writeBlocks(i); //85341 first good is 
        
        
    }
    if(Method == ChainingMethod::GCM){
        if(metaData) this->writeData(bytesLeft,Method,iv,tag);
    } 
    else {
        if(metaData) this->writeData(bytesLeft,Method,iv, nullptr);
    }
    
}

void File::calculateTagWrapper(Key* key, ChainingMethod Method,  IV* iv) {


    int bytesLeft = this->getFileSize()%Block::BLOCK_SIZE;

    std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> AAD;
    for (auto& row : AAD) {
        row.fill(0);
    }

    this->tag = new Block(AAD, key);
    IV* localIV = iv;



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



        if(Method == ChainingMethod::GCM) {
            iv->splitIV();
            this->calculateTag(key,*iv);
        }

        
        
        
    }
    if(Method == ChainingMethod::GCM){
        this->tag->toString();
    } 
    
}


void File::decode(Key* key, bool deprecated) {

    
    Utils::setUseClassicTTables(true);  // Activer les T-tables

    
    key->splitKey();
	key->KeyExpansion();
	this->splitFile(new Padding(Padding::None));

    


    Data data = this->readData();

    ChainingMethod Method = data.getMethod();
    IV* iv = data.getIV();

    std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> AAD;
    for (auto& row : AAD) {
        row.fill(0);
    }



    this->tag = new Block(AAD, key);
    
    this->calculateTagWrapper(key, Method, iv);
    
    IV* localIV = iv;

    
    
    
    for(int i = this->nbFlows - 1; i >= 0; i-=1){
        

        if(i != 0) {
            localIV = this->readIV(i);
        }
        else {
            localIV = iv;
        }


        Utils::showProgressBar(i, this->nbFlows-1);


        if(i == this->nbFlows - 1) {
            // Si sizeLastFlow == 0, cela signifie que le dernier flow est complet
            if(this->sizeLastFlow == 0) {
                // Traiter comme un flow complet
                this->blocks.resize(File::FILE_SIZE_MAX / Block::BLOCK_SIZE);
                this->fillBlocks(key, i);
            } else {
                // Traiter comme un flow partiel
                this->blocks.resize(this->sizeLastFlow);
                this->fillBlocks(key, i);
                this->fillLastBlock(key,i, new Padding(Padding::None));
            }
        }
        else {
            this->blocks.resize( this->nbFlows == 1 ? this->nbblocks : File::FILE_SIZE_MAX / Block::BLOCK_SIZE) ;
            this->fillBlocks(key, i);
        }


        switch(Method) {
            case ChainingMethod::CBC:
            localIV->splitIV();
            this->decodeBlocksCBC(*localIV);
            break;
            case ChainingMethod::ECB:
            deprecated ? this->deprecatedDecodeBlocksECB() : decodeBlocksECB();
            break;
            case ChainingMethod::CTR:
            iv->splitIV();
            this->decodeBlocksCTR(*iv, key, i);
            break;
            case ChainingMethod::GCM:
            iv->splitIV();
            this->decodeBlocksGCM(*iv, key, i, data.getBytesLeft());
            break;
        }

        
        if(i == this->nbFlows - 1) {
            int dePad = this->dePad();
            this->writeBlocks(i, dePad );
        }
        else this->writeBlocks(i);

    }

    if(Method == ChainingMethod::GCM){
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