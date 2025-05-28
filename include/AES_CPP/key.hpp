#pragma once
#include "AES_CPP/file.hpp"
#include <vector>
#include <filesystem>
#include <array>
#include <algorithm> 
#include <cstdint>
#include <iostream>

namespace AES_CPP {

class Key {

    public:
    
        static const int WORD_SIZE = 4;
        static const int MIN_NUMBER_ROUNDS = 10;
        static const std::array<int, 3 > possiblesLengths;
        static const std::array<std::array<uint8_t, 16>, 16> Sbox;
        static const std::array<uint8_t, 10> Rcon;
    
        
        static uint8_t hexCharToByte(char c);
        static uint8_t hexPairToByte(char high, char low);

        /*AES Key expansion functions*/

        static void RotWord(std::array<uint8_t, Key::WORD_SIZE>* word);
        static void SubWord(std::array<uint8_t, Key::WORD_SIZE>* word);
        static uint8_t SBoxSubstitution(uint8_t byte);
        static std::array<uint8_t, 4> WordRcon(int i);
        static void XOR(std::array<uint8_t, Key::WORD_SIZE>* word, std::array<uint8_t, Key::WORD_SIZE> key);
        
        
        Key(std::string key);
        std::vector<uint8_t> getKey();
        std::vector<std::array<uint8_t,4>> getWords();
        std::vector<std::array<uint8_t,4>> getRoundKeysWords();
        void splitKey();
        void KeyExpansion();
        void AddRoundKey(std::array< std::array< uint8_t, File::BLOCK_DIMENSION >, File::BLOCK_DIMENSION>* block, int round);
        void SubBytes(std::array< std::array< uint8_t, File::BLOCK_DIMENSION >, File::BLOCK_DIMENSION>* block);
        


    private:
        std::vector<uint8_t> key;
        std::vector<std::array<uint8_t,4>> words;
        std::vector<std::array<uint8_t,4>> RoundKeysWords;
        int size;


};

}