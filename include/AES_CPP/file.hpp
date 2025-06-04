#pragma once
#include "AES_CPP/block.hpp"
#include "AES_CPP/iv.hpp"
#include "AES_CPP/utils.hpp"
#include "AES_CPP/enums.hpp"
#include <vector>
#include <string>
#include <filesystem>
#include <array>
#include <fstream>
#include <iostream>

namespace AES_CPP {

class File {
    public:
        File(const std::string& filePath);
        std::string getFilePath();
        bool fileExists();
        int getFileSize();
        std::vector<Block>* getBlocks();
        void splitFile(Padding* padding);
        void fillBlocks(Key* key, int flow);
        void fillLastBlock(Key* key, int flow, Padding* padding = nullptr);

        uint8_t dePad();

        static const int FILE_SIZE_MAX = 1024000;
        static const int FLOW_SIZE = FILE_SIZE_MAX / Block::BLOCK_SIZE;
        static void encodeBloc(Block* bloc);

        void encodeBlocksECB();
        void deprecatedEncodeBlocksECB();


        void encodeBlocksCBC(IV iv);
        void decodeBlocksECB();
        void decodeBlocksCBC(IV iv);


        void writeBlocks(int flow, int fin = Block::BLOCK_DIMENSION);
        void encode(Key* key, ChainingMethod Method, IV* iv=nullptr, Padding* padding=nullptr);
        void decode(Key* key, ChainingMethod Method, IV* iv=nullptr);


    private:
        std::string filePath;
        int fileSize;
        std::vector<Block> blocks;
        bool partialBlock;
        int nbFlows;
        int sizeLastFlow;


};


}