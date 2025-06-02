#include "AES_CPP/file.hpp"
#include "AES_CPP/key.hpp"
#include "AES_CPP/block.hpp"
#include "AES_CPP/utils.hpp"
#include "AES_CPP/iv.hpp"

int main() {
	AES_CPP::File* file = new AES_CPP::File("../tmp2/CV_2.pdf");
	std::string s = "9f3c7e1a54b82d6e0c1f4a9b3d6e7c1f";
	AES_CPP::Key* key = new AES_CPP::Key(s);
	AES_CPP::IV iv("3f9a4d7c2b81c6e103fa527e8a4b1d60");
	file->encode(key, AES_CPP::ChainingMethod::CBC, &iv);
	
}
