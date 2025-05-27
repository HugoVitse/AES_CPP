#include "AES_CPP/file.hpp"
#include "AES_CPP/key.hpp"

int main() {
	// AES_CPP::File* file = new AES_CPP::File("./test.txt");
	// file->splitFile();
	// file->fillBlocks();
	std::string s = "9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f";
	AES_CPP::Key* key = new AES_CPP::Key(s);
}
