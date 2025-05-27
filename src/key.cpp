#include "AES_CPP/key.hpp"
#include "AES_CPP/keyException.hpp"

namespace AES_CPP {
   
const std::array<int, 3> Key::possiblesLengths = {128, 192, 256};
const std::array<char, 16> Key::hexadecimalCaracters =  {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

Key::Key(std::string key) {

    if
    ( 
        std::find
        (

            Key::possiblesLengths.begin(),
            Key::possiblesLengths.end(),
            static_cast<int>( key.size()*4 )

        ) == Key::possiblesLengths.end()
    )
    {
        throw KeyException("La taille de la clé n'est pas correct.");
    }

    std::vector<char> chars(key.begin(), key.end());

    for(int i = 0; i < chars.size(); i+=1 ) {

        if
        (
            std::find
            (
                Key::hexadecimalCaracters.begin(),
                Key::hexadecimalCaracters.end(),
                chars[i]
            ) == Key::hexadecimalCaracters.end()
        )
        {
            throw KeyException("Le format de la clé n'est pas hexadécimal");
        }

    }

    this->key.resize(key.size()/2);

    for(int i = 0; i < chars.size(); i+=2 ) {
        this->key[i/2] = hexPairToByte(chars[i], chars[i+1]);
    }

    this->size = key.size()/2;
    
    
}

std::vector<uint8_t> Key::getKey() {
    return this->key;
}

std::vector<std::array<uint8_t,4>> Key::getWords() {
    return this->words;
}

void Key::splitKey() {

    int nbWords = this->size / Key::WORD_SIZE;
    this->words.resize(nbWords);

    for( int i =0; i < nbWords; i+=1 ){
        
        std::copy_n(this->key.begin() + i * Key::WORD_SIZE, Key::WORD_SIZE, this->words[i].begin());

    }

}

uint8_t Key::hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw KeyException("Caractère hexadécimal invalide");
}

uint8_t Key::hexPairToByte(char high, char low) {
    return (Key::hexCharToByte(high) << 4) | Key::hexCharToByte(low);
}

void Key::RotWord(std::array<uint8_t, Key::WORD_SIZE>* word) {
    std::rotate(word->begin(), word->begin()+1, word->end());
}

}