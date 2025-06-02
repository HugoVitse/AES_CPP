#pragma once
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
        static const std::array<uint8_t, 10> Rcon;

        /*AES Key expansion functions*/

        static void RotWord(std::array<uint8_t, Key::WORD_SIZE>* word);
        static void SubWord(std::array<uint8_t, Key::WORD_SIZE>* word);
        static std::array<uint8_t, 4> WordRcon(int i);
        
        
        Key(std::string key);
        std::vector<uint8_t> getKey();
        int getSize();
        int getNbRounds();
        std::vector<std::array<uint8_t,4>> getWords();
        std::vector<std::array<uint8_t,4>>* getRoundKeysWords();
        void splitKey();
        void KeyExpansion();        


    private:
        std::vector<uint8_t> key;
        std::vector<std::array<uint8_t,4>> words;
        std::vector<std::array<uint8_t,4>> RoundKeysWords;
        int nbRounds;
        int size;


};

}