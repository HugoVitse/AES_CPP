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
        static const std::array<int, 3 > possiblesLengths;
        static const std::array<char, 16> hexadecimalCaracters;
    
        
        static uint8_t hexCharToByte(char c);
        static uint8_t hexPairToByte(char high, char low);

        /*AES Key expansion functions*/

        static void RotWord(std::array<uint8_t, Key::WORD_SIZE>* word);
        
        Key(std::string key);
        std::vector<uint8_t> getKey();
        std::vector<std::array<uint8_t,4>> getWords();
        void splitKey();
        


    private:
        std::vector<uint8_t> key;
        std::vector<std::array<uint8_t,4>> words;
        int size;


};

}