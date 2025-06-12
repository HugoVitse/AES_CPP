#pragma once
#include "AES_CPP/block.hpp"
#include <vector>
#include <filesystem>
#include <array>
#include <algorithm> 
#include <cstdint>
#include <iostream>

namespace AES_CPP {

class IV {

    public:
    
        IV(std::string iv);
        IV(std::vector<uint8_t> iv);
        IV();

        std::vector<uint8_t> getIV();
        int getSize();
        std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> getWords();
        void splitIV();
        void toString();



    private:
        std::vector<uint8_t> iv;
        std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> words;
        int size;


};

}