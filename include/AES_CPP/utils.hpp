#pragma once
#include "AES_CPP/key.hpp"
#include "AES_CPP/block.hpp"
#include <filesystem>
#include <array>

namespace AES_CPP {

class Utils {

    
    public:
        Utils();
        static const std::array<std::array<uint8_t, 16>, 16> Sbox;
        static const std::array<std::array<uint8_t, 4>,4> matrix;


        static uint8_t SBoxSubstitution(uint8_t byte);
        static void XOR(std::array<uint8_t, Key::WORD_SIZE>* word, std::array<uint8_t, Key::WORD_SIZE> key);
        static void XOR(Block* block, Block key);

        static uint8_t hexCharToByte(char c);
        static uint8_t hexPairToByte(char high, char low);
        static uint8_t specialMultiplication(uint8_t byte, uint8_t operande);
        static uint8_t MatrixMultiplication(int row, std::array< uint8_t, Block::BLOCK_DIMENSION> column);

        static void ZeroPadding(std::array<uint8_t, Block::BLOCK_SIZE>* flatBlock, int bytesLeft);
        static void PKcs7(std::array<uint8_t, Block::BLOCK_SIZE>* flatBlock, int bytesLeft);

        


};

}