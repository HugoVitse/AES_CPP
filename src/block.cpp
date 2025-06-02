#include "AES_CPP/block.hpp"
#include "AES_CPP/key.hpp"
#include "AES_CPP/utils.hpp"

namespace AES_CPP
{
  
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

void Block::coreRound(int round){
    this->SubBytes();
    this->ShitRows();
    this->MixColumns();
    this->AddRoundKey(round);
}

void Block::initialRound(){
    this->AddRoundKey(0);
}

void Block::finalRound(){
    this->SubBytes();
    this->ShitRows();
    this->AddRoundKey(this->key->getNbRounds());
}

void Block::encode() {
    this->initialRound();
    for(int i=1; i < this->key->getNbRounds(); i+=1){
        this->coreRound(i);
    }
    this->finalRound();

}



} 
