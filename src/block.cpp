#include "AES_CPP/block.hpp"
#include "AES_CPP/key.hpp"
#include "AES_CPP/utils.hpp"
#include <iostream>

namespace AES_CPP
{

//constructors
Block::Block(std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> block, Key* key) {
    this->block = block;
    this->key = key;
}

Block::Block(std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> block) {
    this->block = block;
}

Block::Block() : block{} {} 


std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION>* Block::getBlock() {
    return &this->block;
}



//encryption functions
void Block::AddRoundKey(int round) {
    for(int i=0; i < Block::BLOCK_DIMENSION; i+=1) {
        Utils::XOR( &this->block[i], (*this->key->getRoundKeysWords())[round*Block::BLOCK_DIMENSION+i] );
    }
   
}

void Block::SubBytes(){

    for(int i = 0; i < Block::BLOCK_DIMENSION; i+=1) {
        for(int j = 0; j < Block::BLOCK_DIMENSION; j+=1) {
            (*this->getBlock())[i][j] = Utils::SBoxSubstitution((*this->getBlock())[i][j]);
        }
    }

}

void Block::ShitRows(){

    for(int i = 1; i < Block::BLOCK_DIMENSION; i+=1) {
        for(int k = 0; k < i; k+=1){
            uint8_t tmp = (*this->getBlock())[0][i];
            for(int j = 0; j < Block::BLOCK_DIMENSION - 1; j+=1) {
                (*this->getBlock())[j][i] = (*this->getBlock())[j+1][i];
            }
            (*this->getBlock())[Block::BLOCK_DIMENSION - 1][i] = tmp;
        }
    }
}

void Block::MixColumns() {
    for(int i = 0; i < Block::BLOCK_DIMENSION; i+=1){
        std::array<uint8_t, Block::BLOCK_DIMENSION> tmp = this->block[i];
        for(int j = 0; j < Block::BLOCK_DIMENSION; j+=1){           
            this->block[i][j] = Utils::MatrixMultiplication(j, tmp);
        }
    }
}



//decryption functions
void Block::inverseSubBytes(){

    for(int i = 0; i < Block::BLOCK_DIMENSION; i+=1) {
        for(int j = 0; j < Block::BLOCK_DIMENSION; j+=1) {
            (*this->getBlock())[i][j] = Utils::inverseSBoxSubstitution((*this->getBlock())[i][j]);
        }
    }

}

void Block::inverseShitRows(){


    for(int i = 1; i < Block::BLOCK_DIMENSION; i+=1) {
        for(int k = 0; k < i; k+=1){
            uint8_t tmp = (*this->getBlock())[Block::BLOCK_DIMENSION-1][i];
            for(int j = Block::BLOCK_DIMENSION - 1; j > 0 ; j-=1) {
                (*this->getBlock())[j][i] = (*this->getBlock())[j-1][i];
            }
            (*this->getBlock())[0][i] = tmp;
        }
    }
}

void Block::inverseMixColumns() {
    for(int i = 0; i < Block::BLOCK_DIMENSION; i+=1){
        std::array<uint8_t, Block::BLOCK_DIMENSION> tmp = this->block[i];
        for(int j = 0; j < Block::BLOCK_DIMENSION; j+=1){           
            this->block[i][j] = Utils::MatrixMultiplication(j, tmp, true);
        }
    }
}


//encryption rounds functions
void Block::initialRound(){
    this->AddRoundKey(0);
}

void Block::coreRound(int round){
    if (AES_CPP::Utils::isClassicTTablesEnabled()) {
        // t tables encryption
        std::array<std::array<uint8_t, 4>, Block::BLOCK_DIMENSION> temp = this->block;
        
        
        for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
            uint8_t a0 = temp[col][0];
            uint8_t a1 = temp[(col + 1) % Block::BLOCK_DIMENSION][1];
            uint8_t a2 = temp[(col + 2) % Block::BLOCK_DIMENSION][2];
            uint8_t a3 = temp[(col + 3) % Block::BLOCK_DIMENSION][3];
            
            uint32_t t = AES_CPP::Utils::classicTWord(a0, a1, a2, a3);
            
            // Split 32-bit word back into 4 bytes and write to column 'col'
            this->block[col][0] = static_cast<uint8_t>((t >> 24) & 0xFF);
            this->block[col][1] = static_cast<uint8_t>((t >> 16) & 0xFF);
            this->block[col][2] = static_cast<uint8_t>((t >> 8) & 0xFF);
            this->block[col][3] = static_cast<uint8_t>((t) & 0xFF);
        }
        this->AddRoundKey(round);
        return;
    }
    //standard encryption

    this->SubBytes();
    this->ShitRows();
    this->MixColumns();
    this->AddRoundKey(round);
}


void Block::finalRound(){
    if (AES_CPP::Utils::isClassicTTablesEnabled()) {
        //t tables encryption
        std::array<std::array<uint8_t, 4>, Block::BLOCK_DIMENSION> temp = this->block;
        
        for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
            uint8_t a0 = temp[col][0];
            uint8_t a1 = temp[(col + 1) % Block::BLOCK_DIMENSION][1];
            uint8_t a2 = temp[(col + 2) % Block::BLOCK_DIMENSION][2];
            uint8_t a3 = temp[(col + 3) % Block::BLOCK_DIMENSION][3];
            
            uint32_t t = AES_CPP::Utils::classicFinalWord(a0, a1, a2, a3);
            this->block[col][0] = static_cast<uint8_t>((t >> 24) & 0xFF);
            this->block[col][1] = static_cast<uint8_t>((t >> 16) & 0xFF);
            this->block[col][2] = static_cast<uint8_t>((t >> 8) & 0xFF);
            this->block[col][3] = static_cast<uint8_t>((t) & 0xFF);
        }
        this->AddRoundKey(this->key->getNbRounds());
        return;
    }

    //standard encryption
    this->SubBytes();
    this->ShitRows();
    this->AddRoundKey(this->key->getNbRounds());
}


//decryption rounds functions
void Block::inverseInitialRound(){
    this->AddRoundKey(this->key->getNbRounds());
}

void Block::inverseCoreRound(int round){

    
    if (AES_CPP::Utils::isClassicTTablesEnabled()) {
        //t tables decryption

        std::array<std::array<uint8_t, 4>, Block::BLOCK_DIMENSION> temp = this->block;
        
        for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
            uint8_t a0 = temp[col][0];
            uint8_t a1 = temp[(col + Block::BLOCK_DIMENSION - 1) % Block::BLOCK_DIMENSION][1];
            uint8_t a2 = temp[(col + Block::BLOCK_DIMENSION - 2) % Block::BLOCK_DIMENSION][2];
            uint8_t a3 = temp[(col + Block::BLOCK_DIMENSION - 3) % Block::BLOCK_DIMENSION][3];
            
            uint32_t t = AES_CPP::Utils::classicFinalDecWord(a0, a1, a2, a3);
            this->block[col][0] = static_cast<uint8_t>((t >> 24) & 0xFF);
            this->block[col][1] = static_cast<uint8_t>((t >> 16) & 0xFF);
            this->block[col][2] = static_cast<uint8_t>((t >> 8) & 0xFF);
            this->block[col][3] = static_cast<uint8_t>((t) & 0xFF);
        }
        this->AddRoundKey(this->key->getNbRounds() - round);
        this->inverseMixColumns();
        return;
    }

    //standard decryption
    this->inverseShitRows();
    this->inverseSubBytes();
    this->AddRoundKey(this->key->getNbRounds() - round);
    this->inverseMixColumns();
}

void Block::inverseFinalRound(){
    if (AES_CPP::Utils::isClassicTTablesEnabled()) {
        // Save original state
        std::array<std::array<uint8_t, 4>, Block::BLOCK_DIMENSION> temp = this->block;
        
        for (int col = 0; col < Block::BLOCK_DIMENSION; ++col) {
            // Final-round decryption (InvSubBytes + InvShiftRows)
            // Same pattern as inverseCoreRound
            uint8_t a0 = temp[col][0];
            uint8_t a1 = temp[(col + Block::BLOCK_DIMENSION - 1) % Block::BLOCK_DIMENSION][1];
            uint8_t a2 = temp[(col + Block::BLOCK_DIMENSION - 2) % Block::BLOCK_DIMENSION][2];
            uint8_t a3 = temp[(col + Block::BLOCK_DIMENSION - 3) % Block::BLOCK_DIMENSION][3];
            
            uint32_t t = AES_CPP::Utils::classicFinalDecWord(a0, a1, a2, a3);
            this->block[col][0] = static_cast<uint8_t>((t >> 24) & 0xFF);
            this->block[col][1] = static_cast<uint8_t>((t >> 16) & 0xFF);
            this->block[col][2] = static_cast<uint8_t>((t >> 8) & 0xFF);
            this->block[col][3] = static_cast<uint8_t>((t) & 0xFF);
        }
        this->AddRoundKey(0);
        return;
    }

    this->inverseShitRows();
    this->inverseSubBytes();
    this->AddRoundKey(0);
}


//wrappers
void Block::encode() {
    this->initialRound();
    for(int i=1; i < this->key->getNbRounds(); i+=1){
        this->coreRound(i);
    }
    this->finalRound();

}

void Block::decode() {
    this->inverseInitialRound();
    for(int i=1; i < this->key->getNbRounds(); i+=1){
        this->inverseCoreRound(i);
    }
    this->inverseFinalRound();

}

//comparaison operators
bool operator==(const Block& a, const Block& b) {
    
    bool ret = true;
    
    for(int i = 0; i < Block::BLOCK_DIMENSION; i+=1) {
        for(int j = 0; j < Block::BLOCK_DIMENSION; j+=1) {
            if( a.block[i][j] != b.block[i][j]  ){
                ret = false;
                break;
            }
        }
    }
    
    return ret;
      
}

bool operator!=(const Block& a, const Block& b) {
    
    return !(a==b);
    
}

//utils
void Block::toString() {
    for(auto col : *this->getBlock()){
        for(auto row : col) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)row;
        }
    }

    std::cout << std::endl;

}

} 
