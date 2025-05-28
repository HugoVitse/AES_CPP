#include "AES_CPP/file.hpp"
#include "AES_CPP/key.hpp"

int main() {
	// AES_CPP::File* file = new AES_CPP::File("./test.txt");
	// file->splitFile();
	// file->fillBlocks();
	std::string s = "9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f";
	AES_CPP::Key* key = new AES_CPP::Key(s);
	uint8_t t = AES_CPP::Key::SBoxSubstitution(0x53);
	key->splitKey();
	key->KeyExpansion();

	// for(int i =0; i < key->getRoundKeysWords().size(); i+=1){
	// 	for(int j=0; j<4; j+=1){
	// 		std::cout << std::hex << (int)key->getRoundKeysWords()[i][j];
	// 	}
	// 	std::cout << std::endl;
	// }

	std::array<std::array<uint8_t, 4>, 4> test = {{
		{{0x00, 0x00, 0x01, 0x01}},
		{{0x03, 0x03, 0x07, 0x07}}, 
		{{0x0f, 0x0f, 0x1f, 0x1f}}, 
		{{0x3f, 0x3f, 0x7f, 0x7f}}  
	}};

	key->AddRoundKey(&test, 0);
	key->SubBytes(&test);
	std::cout << std::endl;
	for(int i=0; i<4; i+=1){
		for(int j=0; j<4; j+=1){
			std::cout << std::hex << (int)test[i][j];
		}
	}
	
}
