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
#include <thread>
#include <vector>
#include <future>

namespace AES_CPP {

class Data {

public:
    Data(ChainingMethod Method,IV* iv, Block* tag);
    ChainingMethod getMethod();
    IV* getIV();
    Block* getTag();
private :
    ChainingMethod Method;
    IV* iv;
    Block* tag = nullptr;

};

class File {
    public:
        File(const std::string& filePath, const std::string& outputFilePath);
        std::string getFilePath();
        std::string getOutputFilePath();

        bool fileExists();
        long getFileSize();
        void setFileSize(long size);
        std::vector<Block>* getBlocks();
        void splitFile(Padding* padding);
        void fillBlocks(Key* key, int flow);
        void fillLastBlock(Key* key, int flow, Padding* padding = nullptr);

        uint8_t dePad();

        static const int FILE_SIZE_MAX = 8192;
        static const int FLOW_SIZE = FILE_SIZE_MAX / Block::BLOCK_SIZE;
        static void encodeBloc(Block* bloc);
        static void decodeBloc(Block* bloc);


        void deprecatedEncodeBlocksECB();
        void deprecatedDecodeBlocksECB();
        
        
        
        void encodeBlocksECB();
        void encodeBlocksCBC(IV iv);
        void encodeBlocksCTR(IV iv, Key* key, bool GCM = false);
        void encodeBlocksGCM(IV iv, Key* key);


        void decodeBlocksECB();
        void decodeBlocksCBC(IV iv);
        void decodeBlocksCTR(IV iv, Key* key);
        void decodeBlocksGCM(IV iv, Key* key);

        void calculateTag(Key* key, IV iv);
        Block* getTag();



        void writeBlocks(int flow, int fin = Block::BLOCK_SIZE);
        void writeData(ChainingMethod Method,  IV* iv = nullptr, Block* tag = nullptr);
        Data readData();

        void encode(Key* key, ChainingMethod Method, IV* iv=nullptr, Padding* padding=nullptr, bool deprecated = false);
        void decode(Key* key, bool deprecated = false);


    private:
        std::string filePath;
        std::string outputFilePath;

        long fileSize;
        std::vector<Block> blocks;
        bool partialBlock;
        int nbFlows;
        int sizeLastFlow;
        Block* tag;

};



}