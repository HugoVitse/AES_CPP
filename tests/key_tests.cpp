#include <gtest/gtest.h>
#include "AES_CPP/key.hpp"
#include "AES_CPP/keyException.hpp"

using namespace AES_CPP;

/*---------------length test---------------*/
TEST(KeyTest, ValidKeyLength128) {
    EXPECT_NO_THROW(Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f")); // 16 * 8 = 128
}

TEST(KeyTest, ValidKeyLength192) {
    EXPECT_NO_THROW(Key("a1f3d7c9246e8b1f9d3c7a4e1b2d6f93c5a718bf2c4e9d17")); // 24 * 8 = 192
}

TEST(KeyTest, ValidKeyLength256) {
    EXPECT_NO_THROW(Key("6b9e2d7f1c4a8b7e3f1d6c9a2e7b5d1c8a4f9e7d2b3c6a1f0d7c8b2a9e4f6c30")); // 32 * 8 = 256
}

TEST(KeyTest, InvalidKeyLength) {
    EXPECT_THROW(Key("short"), KeyException); // 5 * 8 = 40
}

/*---------------format test---------------*/

TEST(KeyTest, InvalidKeyFormat) {
    EXPECT_THROW(Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1q"), KeyException); // ends with a 'q' wich is not hexadicmal caracter
}

TEST(KeyTest, HexToBytes) {
    EXPECT_EQ(Key::hexPairToByte('0', '0') , 0x00);      // 0
    EXPECT_EQ(Key::hexPairToByte('F', 'F') , 0xFF);      // 255
    EXPECT_EQ(Key::hexPairToByte('a', '0') , 0xA0);      // minuscule high nibble
    EXPECT_EQ(Key::hexPairToByte('0', 'b') , 0x0B);      // minuscule low nibble
    EXPECT_EQ(Key::hexPairToByte('C', '4') , 0xC4);      // majuscules et chiffres
    EXPECT_EQ(Key::hexPairToByte('9', 'f') , 0x9F);      // mixte chiffre + lettre min
    EXPECT_EQ(Key::hexPairToByte('d', 'E') , 0xDE);      // mixte minuscule + majuscule
    EXPECT_EQ(Key::hexPairToByte('7', '7') , 0x77);      // double chiffre identique
    EXPECT_EQ(Key::hexPairToByte('A', 'a') , 0xAA);      // mixte case haute/basse
    EXPECT_EQ(Key::hexPairToByte('5', 'c') , 0x5C);      // cas courant mi-haut
}

TEST(KeyTest, HexKeyIsParsedCorrectly128) {
    std::string hexKey = "00112233445566778899aabbccddeeff"; // 128 bits
    Key key(hexKey);

    std::vector<uint8_t> expected = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };

    EXPECT_EQ(key.getKey(), expected);
}

TEST(KeyTest, HexKeyIsParsedCorrectly192) {
    std::string hexKey = "00112233445566778899aabbccddeeff1122334455667788"; // 192 bits
    Key key(hexKey);

    std::vector<uint8_t> expected = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88
    };


    EXPECT_EQ(key.getKey(), expected);
}

TEST(KeyTest, HexKeyIsParsedCorrectly256) {
    std::string hexKey = "00112233445566778899aabbccddeeff112233445566778899aabbccddeeff00"; // 256 bits
    Key key(hexKey);

    std::vector<uint8_t> expected = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc,
        0xdd, 0xee, 0xff, 0x00
    };


    EXPECT_EQ(key.getKey(), expected);
}

/*---------------split test---------------*/


TEST(KeyTest, KeyIsSplitCorrectly128) {
    std::string hexKey = "00112233445566778899aabbccddeeff"; // 128 bits
    Key key(hexKey);
    key.splitKey();

    std::vector<std::array<uint8_t,4>> words_expected = {
        {0x00, 0x11, 0x22, 0x33},
        {0x44, 0x55, 0x66, 0x77},
        {0x88, 0x99, 0xaa, 0xbb},
        {0xcc, 0xdd, 0xee, 0xff}
    };

    EXPECT_EQ(key.getWords(), words_expected);
}

TEST(KeyTest, KeyIsSplitCorrectly192) {
    std::string hexKey = "00112233445566778899aabbccddeeff1122334455667788"; // 192 bits
    Key key(hexKey);
    key.splitKey();

    std::vector<std::array<uint8_t,4>> words_expected = {
        {0x00, 0x11, 0x22, 0x33},
        {0x44, 0x55, 0x66, 0x77},
        {0x88, 0x99, 0xaa, 0xbb},
        {0xcc, 0xdd, 0xee, 0xff},
        {0x11, 0x22, 0x33, 0x44},
        {0x55, 0x66, 0x77, 0x88}
    };


    EXPECT_EQ(key.getWords(), words_expected);
}

TEST(KeyTest, KeyIsSplitCorrectly256) {
    std::string hexKey = "00112233445566778899aabbccddeeff112233445566778899aabbccddeeff00"; // 256 bits
    Key key(hexKey);
    key.splitKey();

    std::vector<std::array<uint8_t,4>> words_expected = {
        {0x00, 0x11, 0x22, 0x33},
        {0x44, 0x55, 0x66, 0x77},
        {0x88, 0x99, 0xaa, 0xbb},
        {0xcc, 0xdd, 0xee, 0xff},
        {0x11, 0x22, 0x33, 0x44},
        {0x55, 0x66, 0x77, 0x88},
        {0x99, 0xaa, 0xbb, 0xcc},
        {0xdd, 0xee, 0xff, 0x00}
    };


    EXPECT_EQ(key.getWords(), words_expected);
}

/*---------------rotword test---------------*/

TEST(KeyTest, RotWordTest) {

    std::array<uint8_t,4> word = {0x00, 0x11, 0x22, 0x33};
    std::array<uint8_t,4> word_expected = {0x11, 0x22, 0x33, 0x00};
    Key::RotWord(&word);

    EXPECT_EQ(word, word_expected);
}