#include <gtest/gtest.h>
#include "AES_CPP/key.hpp"
#include "AES_CPP/utils.hpp"
#include "AES_CPP/keyException.hpp"
#include "AES_CPP/utilsException.hpp"
#include <chrono>

using namespace AES_CPP;

std::string readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    std::ostringstream oss;
    oss << file.rdbuf();
    return oss.str();
}


TEST(FileTests, AES_TEST_ECB_PKCS7) {
    
    Utils::setUseClassicTTables(true);
    std::string inputPath = "tests/tmp/random_input.bin";
    std::string encryptedPath = "tests/tmp/encrypted_output.bin";
    std::string decryptedPath = "tests/tmp/decrypted_output.bin";

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);
    Utils::generateRandomBinaryFile(inputPath, File::FILE_SIZE_MAX*10 + 100);
    File f(inputPath, encryptedPath);
    Key* key = new Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    f.encode(key, ChainingMethod::ECB, nullptr, new Padding(Padding::PKcs7));
    File f2(encryptedPath, decryptedPath);
    f2.decode(key);

    std::string original = readFile(inputPath);
    std::string decrypted = readFile(decryptedPath);
    ASSERT_EQ(original, decrypted);
    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);
}

TEST(FileTests, AES_TEST_ECB_ZERO) {

    Utils::setUseClassicTTables(true);
    std::string inputPath = "tests/tmp/random_input.bin";
    std::string encryptedPath = "tests/tmp/encrypted_output.bin";
    std::string decryptedPath = "tests/tmp/decrypted_output.bin";

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);

    Utils::generateRandomBinaryFile(inputPath, File::FILE_SIZE_MAX*150 + 100);

    File f(inputPath, encryptedPath);
    Key* key = new Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    f.encode(key, ChainingMethod::ECB, nullptr, new Padding(Padding::ZeroPadding));

    File f2(encryptedPath, decryptedPath);
    f2.decode(key);

    std::string original = readFile(inputPath);
    std::string decrypted = readFile(decryptedPath);
    ASSERT_EQ(original, decrypted);
    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);
}

TEST(FileTests, AES_TEST_CBC_PKCS7) {

    Utils::setUseClassicTTables(true);
    std::string inputPath = "tests/tmp/random_input.bin";
    std::string encryptedPath = "tests/tmp/encrypted_output.bin";
    std::string decryptedPath = "tests/tmp/decrypted_output.bin";

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);

    Utils::generateRandomBinaryFile(inputPath, File::FILE_SIZE_MAX*150 + 100);

    File f(inputPath, encryptedPath);
    Key* key = new Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    IV* iv = new IV("e3a2b4791c8f5d3072e68a5cf174d9b1");
    f.encode(key, ChainingMethod::CBC, iv, new Padding(Padding::PKcs7));

    File f2(encryptedPath, decryptedPath);
    f2.decode(key);

    std::string original = readFile(inputPath);
    std::string decrypted = readFile(decryptedPath);
    ASSERT_EQ(original, decrypted);
    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);
}

TEST(FileTests, AES_TEST_CBC_ZERO) {

    Utils::setUseClassicTTables(true);
    std::string inputPath = "tests/tmp/random_input.bin";
    std::string encryptedPath = "tests/tmp/encrypted_output.bin";
    std::string decryptedPath = "tests/tmp/decrypted_output.bin";

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);

    Utils::generateRandomBinaryFile(inputPath, File::FILE_SIZE_MAX*150 + 100);

    File f(inputPath, encryptedPath);
    Key* key = new Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    IV* iv = new IV("e3a2b4791c8f5d3072e68a5cf174d9b1");
    f.encode(key, ChainingMethod::CBC, iv, new Padding(Padding::ZeroPadding));

    File f2(encryptedPath, decryptedPath);
    f2.decode(key);

    std::string original = readFile(inputPath);
    std::string decrypted = readFile(decryptedPath);
    ASSERT_EQ(original, decrypted);
    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);
}

TEST(FileTests, AES_TEST_CTR_PKCS7) {

    std::string inputPath = "tests/tmp/random_input.bin";
    std::string encryptedPath = "tests/tmp/encrypted_output.bin";
    std::string decryptedPath = "tests/tmp/decrypted_output.bin";

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);

    Utils::generateRandomBinaryFile(inputPath, File::FILE_SIZE_MAX*150 + 100);

    File f(inputPath, encryptedPath);
    Key* key = new Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    IV* iv = new IV("e3a2b4791c8f5d3072e68a5cf174d9b1");
    f.encode(key, ChainingMethod::CTR, iv, new Padding(Padding::PKcs7));

    File f2(encryptedPath, decryptedPath);
    f2.decode(key);

    std::string original = readFile(inputPath);
    std::string decrypted = readFile(decryptedPath);
    ASSERT_EQ(original, decrypted);
    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);
}

TEST(FileTests, AES_TEST_CTR_ZERO) {

    std::string inputPath = "tests/tmp/random_input.bin";
    std::string encryptedPath = "tests/tmp/encrypted_output.bin";
    std::string decryptedPath = "tests/tmp/decrypted_output.bin";

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);

    Utils::generateRandomBinaryFile(inputPath, File::FILE_SIZE_MAX*150 + 100);

    File f(inputPath, encryptedPath);
    Key* key = new Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    IV* iv = new IV("e3a2b4791c8f5d3072e68a5cf174d9b1");
    f.encode(key, ChainingMethod::CTR, iv, new Padding(Padding::ZeroPadding));

    File f2(encryptedPath, decryptedPath);
    f2.decode(key);

    std::string original = readFile(inputPath);
    std::string decrypted = readFile(decryptedPath);
    ASSERT_EQ(original, decrypted);
    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);
}

TEST(FileTests, AES_TEST_GCM_PKCS7) {

    std::string inputPath = "tests/tmp/random_input.bin";
    std::string encryptedPath = "tests/tmp/encrypted_output.bin";
    std::string decryptedPath = "tests/tmp/decrypted_output.bin";

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);

    Utils::generateRandomBinaryFile(inputPath, 200*1024*1024 + 100);

    File f(inputPath, encryptedPath);
    Key* key = new Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    IV* iv = new IV("e3a2b4791c8f5d3072e68a5cf174d9b1");

    // Measure encryption throughput (bytes / second)
    auto file_size = std::filesystem::file_size(inputPath);
    auto start = std::chrono::high_resolution_clock::now();
    f.encode(key, ChainingMethod::GCM, iv, new Padding(Padding::PKcs7));
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    double seconds = elapsed.count();
    double mb = static_cast<double>(file_size) / (1024.0 * 1024.0);
    double throughput_mb_s = seconds > 0.0 ? (mb / seconds) : 0.0;

    File f2(encryptedPath, decryptedPath);
    f2.decode(key);

    std::string original = readFile(inputPath);
    std::string decrypted = readFile(decryptedPath);
    ASSERT_EQ((*f.getTag()), (*f2.getTag()));
    ASSERT_EQ(original, decrypted);

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);
}

TEST(FileTests, AES_TEST_GCM_ZERO) {

    std::string inputPath = "tests/tmp/random_input.bin";
    std::string encryptedPath = "tests/tmp/encrypted_output.bin";
    std::string decryptedPath = "tests/tmp/decrypted_output.bin";

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);

    Utils::generateRandomBinaryFile(inputPath, File::FILE_SIZE_MAX*150 + 100);

    File f(inputPath, encryptedPath);
    Key* key = new Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");
    IV* iv = new IV("e3a2b4791c8f5d3072e68a5cf174d9b1");
    f.encode(key, ChainingMethod::GCM, iv, new Padding(Padding::ZeroPadding));

    File f2(encryptedPath, decryptedPath);
    f2.decode(key);

    std::string original = readFile(inputPath);
    std::string decrypted = readFile(decryptedPath);
    ASSERT_EQ((*f.getTag()), (*f2.getTag()));
    ASSERT_EQ(original, decrypted);
    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);
}

TEST(FileTests, SpeedTest) {

    std::string inputPath = "tests/tmp/random_input.bin";
    std::string encryptedPath = "tests/tmp/encrypted_output.bin";
    std::string decryptedPath = "tests/tmp/decrypted_output.bin";

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);
    
    Utils::generateRandomBinaryFile(inputPath, File::FILE_SIZE_MAX*150 + 200);
    File f(inputPath, encryptedPath);
    Key* key = new Key("9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f");

    auto start = std::chrono::high_resolution_clock::now();
    f.encode(key, ChainingMethod::ECB, nullptr, new Padding(Padding::PKcs7));

    File f2(encryptedPath, decryptedPath);
    f2.decode(key);

    std::string original = readFile(inputPath);
    std::string decrypted = readFile(decryptedPath);

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = end - start;





    Utils::generateRandomBinaryFile(inputPath, File::FILE_SIZE_MAX*150 + 200);
    File _f(inputPath, encryptedPath);
    start = std::chrono::high_resolution_clock::now();
    
    _f.encode(key, ChainingMethod::ECB, nullptr, new Padding(Padding::PKcs7), true);

    File _f2(encryptedPath, decryptedPath);
    _f2.decode(key, true);

    original = readFile(inputPath);
    decrypted = readFile(decryptedPath);

    std::filesystem::remove(inputPath);
    std::filesystem::remove(encryptedPath);
    std::filesystem::remove(decryptedPath);

    end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration_2 = end - start;

    ASSERT_LE(duration,duration_2);

}