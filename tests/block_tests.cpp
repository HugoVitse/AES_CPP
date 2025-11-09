#include <gtest/gtest.h>
#include "AES_CPP/key.hpp"
#include "AES_CPP/utils.hpp"
#include "AES_CPP/keyException.hpp"
#include "AES_CPP/utilsException.hpp"

using namespace AES_CPP;

TEST(BlockTest, AddRoundBlockTestRound0) {

    Key key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    std::array< std::array<uint8_t,4>,4> test = {{
        {{0x00, 0x00, 0x01, 0x01}}, 
        {{0x03, 0x03, 0x07, 0x07}}, 
        {{0x0f, 0x0f, 0x1f, 0x1f}}, 
        {{0x3f, 0x3f, 0x7f, 0x7f}}  
    }};

    Block testBlock = Block(test, &key);

    std::array<std::array<uint8_t, 4>, 4> expectedXored = {{
        {{0x9f, 0x3c, 0x7f, 0x1b}}, 
        {{0x57, 0xbb, 0x2a, 0x69}}, 
        {{0x03, 0x10, 0x55, 0x84}}, 
        {{0x02, 0x51, 0x03, 0x60}}  
    }};

    Block expectedXoredBlock = Block(expectedXored, &key);
    

    key.splitKey();
    key.KeyExpansion();
    testBlock.AddRoundKey(0);

    EXPECT_EQ(*testBlock.getBlock(), *expectedXoredBlock.getBlock());

}

TEST(BlockTest, SubBytesTest) {

    Key key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    std::array< std::array<uint8_t,4>,4> test = {{
        {{0x00, 0x00, 0x01, 0x01}}, 
        {{0x03, 0x03, 0x07, 0x07}}, 
        {{0x0f, 0x0f, 0x1f, 0x1f}}, 
        {{0x3f, 0x3f, 0x7f, 0x7f}}  
    }};

    Block testBlock = Block(test, &key);

    std::array<std::array<uint8_t, 4>, 4> expectedSubbed =  {{
        {{0xdb, 0xeb, 0xd2, 0xaf}}, 
        {{0x5b, 0xea, 0xe5, 0xf9}},
        {{0x7b, 0xca, 0xfc, 0x5f}},
        {{0x77, 0xd1, 0x7b, 0xd0}}  
    }};

    Block expectedSubbedBlock = Block(expectedSubbed, &key);

    

    key.splitKey();
    key.KeyExpansion();
    testBlock.AddRoundKey(0);
    testBlock.SubBytes();

    EXPECT_EQ(*testBlock.getBlock(), *expectedSubbedBlock.getBlock());

}

TEST(BlockTest, ShiftRows) {

    Key key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    std::array< std::array<uint8_t,4>,4> test = {{
        {{0x00, 0x00, 0x01, 0x01}}, 
        {{0x03, 0x03, 0x07, 0x07}}, 
        {{0x0f, 0x0f, 0x1f, 0x1f}}, 
        {{0x3f, 0x3f, 0x7f, 0x7f}}  
    }};

    Block testBlock = Block(test, &key);

    std::array<std::array<uint8_t, 4>, 4> expectedShifted =  {{
        {{0xdb, 0xea, 0xfc, 0xd0}},
        {{0x5b, 0xca, 0x7b, 0xaf}},
        {{0x7b, 0xd1, 0xd2, 0xf9}}, 
        {{0x77, 0xeb, 0xe5, 0x5f}}  
    }};
    
    Block expectedShiftedBlock = Block(expectedShifted, &key);


    key.splitKey();
    key.KeyExpansion();
    testBlock.AddRoundKey(0);
    testBlock.SubBytes();
    testBlock.ShitRows();

    EXPECT_EQ(*testBlock.getBlock(), *expectedShiftedBlock.getBlock());

}

TEST(BlockTest, MixColumnsTest) {
    Utils::setUseClassicTTables(true);

    Key key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    std::array< std::array<uint8_t,4>,4> test = {{
        {{0x00, 0x00, 0x01, 0x01}}, 
        {{0x03, 0x03, 0x07, 0x07}}, 
        {{0x0f, 0x0f, 0x1f, 0x1f}}, 
        {{0x3f, 0x3f, 0x7f, 0x7f}}  
    }};

    Block testBlock = Block(test, &key);

    std::array<std::array<uint8_t, 4>, 4> expectedMixed =  {{
        {{0xa4, 0xdb, 0xb9, 0xdb}}, 
        {{0x27, 0xf6, 0x8d, 0x19}}, 
        {{0xb5, 0x56, 0x05, 0x67}},
        {{0x72, 0xd1, 0xac, 0x29}} 
    }};
    
    Block expectedMixedBlock = Block(expectedMixed, &key);


    key.splitKey();
    key.KeyExpansion();
    testBlock.AddRoundKey(0);
    testBlock.SubBytes();
    testBlock.ShitRows();
    testBlock.MixColumns();

    EXPECT_EQ(*testBlock.getBlock(), *expectedMixedBlock.getBlock());

}

TEST(BlockTest, Round1Test) {

    Utils::setUseClassicTTables(true);

    Key key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    std::array< std::array<uint8_t,4>,4> test = {{
        {{0x00, 0x00, 0x01, 0x01}}, 
        {{0x03, 0x03, 0x07, 0x07}}, 
        {{0x0f, 0x0f, 0x1f, 0x1f}}, 
        {{0x3f, 0x3f, 0x7f, 0x7f}}  
    }};

    Block testBlock = Block(test, &key);

    std::array<std::array<uint8_t, 4>, 4> expectedRound1 =  {{
        {{0xa5, 0xf7, 0x07, 0xe6}}, 
        {{0x72, 0x62, 0x1e, 0x4a}}, 
        {{0xec, 0xdd, 0xdc, 0xaf}}, 
        {{0x16, 0x34, 0x09, 0xfe}}  
    }};
    
    Block expectedRound1Block = Block(expectedRound1, &key);


    key.splitKey();
    key.KeyExpansion();
    testBlock.AddRoundKey(0);
    testBlock.coreRound(1);

    EXPECT_EQ(*testBlock.getBlock(), *expectedRound1Block.getBlock());

}

TEST(BlockTest, FinalRoundTest) {

    Utils::setUseClassicTTables(true);

    Key key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    std::array< std::array<uint8_t,4>,4> test = {{
        {{0x61, 0xe1, 0x55, 0x3d}}, 
        {{0xca, 0x3d, 0xc8, 0x97}}, 
        {{0xf1, 0x4b, 0x48, 0xb0}}, 
        {{0x03, 0xd2, 0x80, 0x87}}  
    }};

    Block testBlock = Block(test, &key);

    std::array<std::array<uint8_t, 4>, 4> expectedFinalRound =  {{
        {{0xab, 0xc4, 0xa2, 0x98}}, 
        {{0xc3, 0x01, 0xa8, 0x20}}, 
        {{0x57, 0xd5, 0xb0, 0xe2}}, 
        {{0x73, 0xd4, 0x86, 0x46}}  
    }};
    
    Block expectedFinalRoundBlock = Block(expectedFinalRound, &key);


    key.splitKey();
    key.KeyExpansion();
    testBlock.finalRound();

    EXPECT_EQ(*testBlock.getBlock(), *expectedFinalRoundBlock.getBlock());

}

TEST(BlockTest, EncondingTest) {

    Utils::setUseClassicTTables(true);

    Key key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    std::array< std::array<uint8_t,4>,4> test = {{
        {{0x00, 0x00, 0x01, 0x01}}, 
        {{0x03, 0x03, 0x07, 0x07}}, 
        {{0x0f, 0x0f, 0x1f, 0x1f}}, 
        {{0x3f, 0x3f, 0x7f, 0x7f}}  
    }};

    Block testBlock = Block(test, &key);

    std::array<std::array<uint8_t, 4>, 4> expectedEncoded =  {{
        {{0xab, 0xc4, 0xa2, 0x98}}, 
        {{0xc3, 0x01, 0xa8, 0x20}}, 
        {{0x57, 0xd5, 0xb0, 0xe2}}, 
        {{0x73, 0xd4, 0x86, 0x46}}  
    }};
    
    Block expectedEncodedBlock = Block(expectedEncoded, &key);


    key.splitKey();
    key.KeyExpansion();
    testBlock.encode();

    EXPECT_EQ(*testBlock.getBlock(), *expectedEncodedBlock.getBlock());

}
TEST(BlockTest, EncondingTest2) {

    Utils::setUseClassicTTables(true);

    Key key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    std::array< std::array<uint8_t,4>,4> test = {{
        {{0x74, 0x65, 0x73, 0x74}}, 
        {{0x00, 0x00, 0x00, 0x00}}, 
        {{0x00, 0x00, 0x00, 0x00}}, 
        {{0x00, 0x00, 0x00, 0x00}}, 
    }};

    Block testBlock = Block(test, &key);

    std::array<std::array<uint8_t, 4>, 4> expectedEncoded =  {{
        {{0x99, 0xb8, 0x26, 0x81}}, // Colonne 0
        {{0x10, 0x31, 0xd4, 0xa9}}, // Colonne 1
        {{0x42, 0x5e, 0xeb, 0xdc}}, // Colonne 2
        {{0x27, 0x72, 0xc1, 0x2e}}  // Colonne 3
    }};
    
    Block expectedEncodedBlock = Block(expectedEncoded, &key);


    key.splitKey();
    key.KeyExpansion();
    testBlock.encode();

    EXPECT_EQ(*testBlock.getBlock(), *expectedEncodedBlock.getBlock());

}