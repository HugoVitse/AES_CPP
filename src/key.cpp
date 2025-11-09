#include "AES_CPP/key.hpp"
#include "AES_CPP/keyException.hpp"
#include "AES_CPP/file.hpp"
#include "AES_CPP/utils.hpp"
#include <iomanip>

namespace AES_CPP {
   
const std::array<int, 3> Key::possiblesLengths = {128, 192, 256};
const std::array<uint8_t, 10> Key::Rcon = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

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
    this->key.resize(key.size()/2);

    for(int i = 0; i < chars.size(); i+=2 ) {
        this->key[i/2] = Utils::hexPairToByte(chars[i], chars[i+1]);
    }

    this->size = key.size()/2;
    
    
}

std::vector<uint8_t> Key::getKey() {
    return this->key;
}

int Key::getSize() {
    return this->size;
}

int Key::getNbRounds() {
    return this->nbRounds;
}

std::vector<std::array<uint8_t,4>>* Key::getRoundKeysWords() {
    return &this->RoundKeysWords;
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

void Key::RotWord(std::array<uint8_t, Key::WORD_SIZE>* word) {
    std::rotate(word->begin(), word->begin()+1, word->end());
}

void Key::SubWord(std::array<uint8_t, Key::WORD_SIZE>* word) {
    for(int i=0; i < word->size(); i+=1){
        (*word)[i] = Utils::SBoxSubstitution(word->at(i));
    }
}

std::array<uint8_t, 4> Key::WordRcon(int i){
    return std::array<uint8_t,4>({Rcon[i], 0x00, 0x00, 0x00});
}


void Key::KeyExpansion() {
    int Nk = this->size / Key::WORD_SIZE;
    int Nb = Block::BLOCK_SIZE / Key::WORD_SIZE;
    int Nr = Key::MIN_NUMBER_ROUNDS + Nk - 4;

    this->nbRounds = Nr;

    int nbWords = Nb * (Nr + 1);
    this->RoundKeysWords.resize(nbWords);

    for(int i = 0; i < nbWords; i+=1) {

        if (i < Nk) {
            this->RoundKeysWords[i] = this->words[i];
        }

        else {
            std::array<uint8_t, Key::WORD_SIZE> tmp = this->RoundKeysWords[i-1];
            if(i%Nk == 0) {
                Key::RotWord(&tmp);
                Key::SubWord(&tmp);
                Utils::XOR(&tmp, Key::WordRcon( i / Nk - 1));
            }
            if(i%Nk == 4 && Nk == 8) {
                Key::SubWord(&tmp);
            }
            Utils::XOR(&tmp, this->RoundKeysWords[i - Nk]);
            this->RoundKeysWords[i] = tmp;
        }

    }

    (void)nbWords; // no diagnostic output in production code

}


}