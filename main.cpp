#include "AES_CPP/utils.hpp"

int main(int argc, char* argv[]) {


	try {
       AES_CPP::Utils::handleInput(argc, argv);

    } catch (const std::exception& e) {
        std::cerr << "Erreur : " << e.what() << std::endl;
        return 1;
    }

    return 0;
	
}
