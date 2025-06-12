#include "AES_CPP/iv.hpp"
#include "AES_CPP/ivException.hpp"
#include "AES_CPP/file.hpp"
#include "AES_CPP/utils.hpp"

namespace AES_CPP {

IV::IV(std::string iv) {

    if ( static_cast<int>( iv.size()*4 ) > 128) {
        throw IVException("La taille de la clé n'est pas correct.");
    }

    std::vector<char> chars(iv.begin(), iv.end());
    this->iv.resize(iv.size()/2);

    for(int i = 0; i < chars.size(); i+=2 ) {
        this->iv[i/2] = Utils::hexPairToByte(chars[i], chars[i+1]);
    }

    this->size = iv.size()/2;
    
    
}

IV::IV(std::vector<uint8_t> iv) {

    this->iv = iv;
    this->size = iv.size()/2;  
    
}

std::vector<uint8_t> IV::getIV() {
    return this->iv;
}

int IV::getSize() {
    return this->size;
}

std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> IV::getWords() {
    return this->words;
}

void IV::splitIV() {

    for( int i =0; i < Block::BLOCK_DIMENSION; i+=1 ){
        
        std::copy_n(this->iv.begin() + i * Key::WORD_SIZE, Key::WORD_SIZE, this->words[i].begin());

    }

}

void IV::toString() {
    for(auto col : this->getWords()){
        for(auto row : col) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)row;
        }
    }

    std::cout << std::endl;


}

}