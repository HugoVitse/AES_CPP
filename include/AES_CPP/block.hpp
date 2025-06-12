#pragma once
#include "AES_CPP/key.hpp"
#include <array>
#include <filesystem>
#include <vector>

namespace AES_CPP {

class Block {
    public:
        static const int BLOCK_DIMENSION = 4;
        static const int BLOCK_SIZE = 16;
        Block(std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> block, Key* key);
        Block(std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> block);

        Block();

        std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION>* getBlock();

        void AddRoundKey(int round);
        void SubBytes();
        void ShitRows();
        void MixColumns();

        void inverseSubBytes();
        void inverseShitRows();
        void inverseMixColumns();

        void initialRound();
        void coreRound(int round);
        void finalRound();

        void inverseInitialRound();
        void inverseCoreRound(int round);
        void inverseFinalRound();


        void encode();
        void decode();

        void toString();

        friend bool operator==(const Block& a, const Block& b);
        friend bool operator!=(const Block& a, const Block& b);



    private:

        Key* key;
        std::array< std::array< uint8_t, Block::BLOCK_DIMENSION >, Block::BLOCK_DIMENSION> block;
};


}