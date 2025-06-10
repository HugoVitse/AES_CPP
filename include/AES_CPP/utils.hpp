#pragma once
#include "AES_CPP/key.hpp"
#include "AES_CPP/block.hpp"
#include "AES_CPP/enums.hpp"
#include "AES_CPP/file.hpp"
#include <boost/program_options.hpp>
#include <filesystem>
#include <array>
#include <fstream>
#include <random>
#include <filesystem>

namespace AES_CPP {

class Utils {

    
    public:
        Utils();
        static const std::array<std::array<uint8_t, 16>, 16> Sbox;
        static const std::array<std::array<uint8_t, 16>, 16> inverseSbox;

        static const std::array<std::array<uint8_t, 4>,4> matrix;
        static const std::array<std::array<uint8_t, 4>,4> inverseMatrix;



        static uint8_t SBoxSubstitution(uint8_t byte);
        static uint8_t inverseSBoxSubstitution(uint8_t byte);
        static uint8_t xtime(uint8_t x);


        static void XOR(std::array<uint8_t, Key::WORD_SIZE>* word, std::array<uint8_t, Key::WORD_SIZE> key);
        static void XOR(Block* block, Block key);

        static uint8_t hexCharToByte(char c);
        static uint8_t hexPairToByte(char high, char low);
        static uint8_t specialMultiplication(uint8_t byte, uint8_t operande);
        static uint8_t MatrixMultiplication(int row, std::array< uint8_t, Block::BLOCK_DIMENSION> column, bool inverse=false);

        static void ZeroPadding(std::array<uint8_t, Block::BLOCK_SIZE>* flatBlock, int bytesLeft);
        static void PKcs7(std::array<uint8_t, Block::BLOCK_SIZE>* flatBlock, int bytesLeft);


        static ChainingMethod parseChaining(const std::string& str);
        static Padding parsePadding(const std::string& str);
        static void validate(boost::any& v, const std::vector<std::string>& values, AES_CPP::Padding*, int);
        static void validate(boost::any& v, const std::vector<std::string>& values, AES_CPP::ChainingMethod*, int);
        static void handleInput(int argc, char* argv[]);

        static void showProgressBar(int progress, int total);

        static void generateRandomBinaryFile(const std::string& path, size_t size);


        


};

}