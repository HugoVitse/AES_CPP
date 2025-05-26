#include <iostream>
#include "AES_CPP/file.hpp"

int main() {
	AES_CPP::File* file = new AES_CPP::File("./cr.sh");
	std::cout << file->getFileSize() << std::endl;
}
