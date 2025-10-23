#include "AES_CPP/utils.hpp"
#include "AES_CPP/utilsException.hpp"

namespace po = boost::program_options;

namespace AES_CPP {

const std::array<std::array<u_int8_t, 16>, 16> Utils::Sbox = {{
    {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}},
    {{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}},
    {{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}},
    {{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}},
    {{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}},
    {{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}},
    {{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}},
    {{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}},
    {{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}},
    {{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}},
    {{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}},
    {{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}},
    {{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}},
    {{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}},
    {{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}},
    {{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}}
}};

const std::array<std::array<uint8_t, 16>, 16> Utils::inverseSbox = {{
    {{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB}},
    {{0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB}},
    {{0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E}},
    {{0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25}},
    {{0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92}},
    {{0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84}},
    {{0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06}},
    {{0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B}},
    {{0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73}},
    {{0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E}},
    {{0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B}},
    {{0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4}},
    {{0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F}},
    {{0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF}},
    {{0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61}},
    {{0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}}
}};

const std::array<std::array<uint8_t, 4>,4> Utils::matrix = {{
    {{2,3,1,1}},
    {{1,2,3,1}},
    {{1,1,2,3}},
    {{3,1,1,2}}
}};

const std::array<std::array<uint8_t, 4>,4> Utils::inverseMatrix = {{
    {{14,11,13,9}},
    {{9,14,11,13}},
    {{13,9,14,11}},
    {{11,13,9,14}}
}};

Utils::Utils() {}

uint8_t Utils::SBoxSubstitution(uint8_t byte) {
    uint8_t high = byte >> 4;
    uint8_t low = byte & 0x0F;
    
    return Utils::Sbox[high][low];
    
}

uint8_t Utils::inverseSBoxSubstitution(uint8_t byte) {
    uint8_t high = byte >> 4;
    uint8_t low = byte & 0x0F;
    
    return Utils::inverseSbox[high][low];
    
}

void Utils::XOR(std::array<uint8_t, Key::WORD_SIZE>* word, std::array<uint8_t, Key::WORD_SIZE> key) {
    for(int i = 0; i < word->size(); i+=1) {
        (*word)[i] ^= key[i];
    }
    
}

void Utils::XOR(Block* block, Block key) {
    for(int i = 0; i < Block::BLOCK_DIMENSION; i+=1) {
        Utils::XOR( &(*block->getBlock())[i], (*key.getBlock())[i]);
    }
    
}

uint8_t Utils::hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw UtilException("Caractère hexadécimal invalide");
}

uint8_t Utils::hexPairToByte(char high, char low) {
    return (Utils::hexCharToByte(high) << 4) | Utils::hexCharToByte(low);
}

uint8_t Utils::xtime(uint8_t x) {
    return (x & 0x80) ? ((x << 1) ^ 0x1B) & 0xFF : (x << 1);
}

uint8_t Utils::specialMultiplication(uint8_t byte, uint8_t operande) {
    uint8_t result = 0;
    while (operande) {
        if (operande & 1) {
            result ^= byte; 
        }
        byte = (byte & 0x80) ? ((byte << 1) ^ 0x1B) : (byte << 1);
        operande >>= 1;
    }
    return result;
}


uint8_t Utils::MatrixMultiplication(int row, std::array< uint8_t, Block::BLOCK_DIMENSION> column, bool inverse) {

    uint8_t result = 0;

    for(int i = 0; i < Block::BLOCK_DIMENSION; i+=1) {
        uint8_t tmp = Utils::specialMultiplication(column[i], (inverse ? Utils::inverseMatrix : Utils::matrix)[row][i]);
        result ^= tmp;
    }

    return result;

}

void Utils::blockMultiplication (Block* block, Block operande){

    for(int i = 0; i < Block::BLOCK_DIMENSION; i+=1){
        for(int j = 0; j < Block::BLOCK_DIMENSION; j+=1) {
            (*block->getBlock())[i][j] = Utils::specialMultiplication((*block->getBlock())[i][j], (*operande.getBlock())[i][j]);
        }
    }

}



void Utils::ZeroPadding(std::array<uint8_t, Block::BLOCK_SIZE>* flatBlock, int bytesLeft) {
    for(int i = bytesLeft; i < Block::BLOCK_SIZE; i+=1) {
        (*flatBlock)[i] = 0;
    }

}

void Utils::PKcs7(std::array<uint8_t, Block::BLOCK_SIZE>* flatBlock, int bytesLeft) {
    for(int i = bytesLeft; i < Block::BLOCK_SIZE; i+=1) {
        (*flatBlock)[i] = static_cast<u_int8_t> (Block::BLOCK_SIZE - bytesLeft);
    }
    
}

bool Utils::increment_iv_be(IV &iv, bool flag) {
    if(flag) {
        iv.splitIV();
        iv.toString();
    }
    for (int i = 15; i >= 0; --i) {
        if (++iv.getIV()[i] != 0){
            iv.splitIV();
            if(flag) iv.toString();
            return true; // pas de retenue -> fini
        } 
    }
    // Overflow : on a roulé sur 0...0
    return false;
}

void Utils::add_to_iv_be(IV &iv, size_t value) {
    // Ajouter 'value' à l'IV traité comme un grand entier big-endian (128 bits)
    // On commence par le byte le plus à droite (index 15) et on propage la retenue
    uint64_t carry = value;
    
    for (int i = 15; i >= 0 && carry > 0; --i) {
        uint64_t sum = static_cast<uint64_t>(iv.getIV()[i]) + carry;
        iv.getIV()[i] = static_cast<uint8_t>(sum & 0xFF);
        carry = sum >> 8;  // La retenue pour le prochain byte
    }
    
    iv.splitIV();
}


void Utils::showProgressBar(int progress, int total) {
    const int barWidth = 50;
    float ratio = static_cast<float>(progress) / total;
    int pos = static_cast<int>(barWidth * ratio);

    std::cout << "[";
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << int(ratio * 100.0) << " %\r";
    std::cout.flush();
}

ChainingMethod Utils::parseChaining(const std::string& str) {
    if (str == "ECB") return ChainingMethod::ECB;
    if (str == "CBC") return ChainingMethod::CBC;
    if (str == "CTR") return ChainingMethod::CTR;
    if (str == "GCM") return ChainingMethod::GCM;
    throw po::validation_error(po::validation_error::invalid_option_value, "chaining method", str);
}

Padding parsePadding(const std::string& str) {
    if (str == "ZERO") return Padding::ZeroPadding;
    if (str == "PKCS7") return Padding::PKcs7;
    throw po::validation_error(po::validation_error::invalid_option_value, "padding", str);
}

void validate(boost::any& v, const std::vector<std::string>& values, AES_CPP::ChainingMethod*, int) {
    po::validators::check_first_occurrence(v);
    const std::string& s = po::validators::get_single_string(values);
    v = Utils::parseChaining(s);
}

void validate(boost::any& v, const std::vector<std::string>& values, AES_CPP::Padding*, int) {
    po::validators::check_first_occurrence(v);
    const std::string& s = po::validators::get_single_string(values);
    v = AES_CPP::parsePadding(s);
}



void Utils::handleInput(int argc, char* argv[]){

    std::string filename;
    std::string outputFilename;

    std::string key;
    std::string iv;
    AES_CPP::ChainingMethod chainingMethod;
    AES_CPP::Padding padding;

    bool decode = false;
    bool encode = false;
    
    bool meta = true;


    po::options_description desc("Options disponibles");
    desc.add_options()
        ("help,h", "Afficher l'aide")
        ("file,f", po::value<std::string>(&filename), "Nom du fichier")
        ("key,k", po::value<std::string>(&key), "Clé de chiffrement (hex)")
        ("iv,i", po::value<std::string>(&iv), "Vecteur d'initialisation")
        ("chaining,c", po::value<AES_CPP::ChainingMethod>(&chainingMethod), "Méthode de chaînage (ECB, CBC, CTR, GCM)")
        ("padding,p", po::value<AES_CPP::Padding>(&padding), "Type de padding (ZERO, PKCS7)")
        ("decode,d", po::bool_switch(&decode), "Mode déchiffrement")
        ("encode,e", po::bool_switch(&encode), "Mode chiffrement")
        ("output,o", po::value<std::string>(&outputFilename), "Fichier de sortie")
        ("meta,m", po::value<bool>(&meta)->default_value(true)->implicit_value(false), "Désactiver l'écriture des métadonnées");


    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if(meta) std::cout << "blablaok" << std::endl;
    if(!decode && !encode) {
        throw UtilException("Selectionnez un mode (--encode ou --decode)");
    }

    if(decode && encode) {
        throw UtilException("Ne selectionnez qu'un mode à la fois (--encode ou --decode)");
    }

    if (vm.count("help")) {
        std::cout << desc << std::endl;
    }

    if (vm.count("file")) {
        std::cout << "Fichier : " << filename << std::endl;
    } else {
        throw UtilException("Erreur : aucun fichier spécifié (--file)");
    }

    if (vm.count("key")) {
        std::cout << "Clé : " << key << std::endl;
    }
    else {
        throw UtilException("Précisez une clé de chiffrement héxadécimale");
    }
    
    if(encode) {
        if (vm.count("chaining")) {
            std::cout << "Méthode de chaînage définie." << std::endl;
        }
        else {
            std::cout << "Aucune méthode de chaînage précisée. CBC utilisée par défault" << std::endl;
            chainingMethod = ChainingMethod::CBC;
        }

        
        if (vm.count("iv")) {
            std::cout << "IV : " << iv << std::endl;
        }

        if( (chainingMethod == ChainingMethod::CBC || chainingMethod == ChainingMethod::CTR || chainingMethod == ChainingMethod::GCM) && !vm.count("iv")) {
            std::cout << "IV non précisé, généré aléatoirement" << std::endl;
            iv = Utils::generateRandomIV();
            std::cout << "IV : " << iv << std::endl;

        }

        if (vm.count("padding")) {
            std::cout << "Padding défini." << std::endl;
        }
        else {
            std::cout << "Aucune méthode de padding précisée. PKCS7 utilisée par défault" << std::endl;
            padding = Padding::PKcs7;
        }
    }


    if (vm.count("output")) {
        std::cout << "Fichier de sortie : " << outputFilename << std::endl;
    }
    else {
        outputFilename = filename;
    }
    File* _file = new File(filename, outputFilename);
    Key* _key = new AES_CPP::Key(key);
    IV* _iv = nullptr;

    if(chainingMethod == ChainingMethod::CBC || chainingMethod == ChainingMethod::CTR || chainingMethod == ChainingMethod::GCM) {
        _iv = new IV(iv);
    }

    if(decode) _file->decode(_key);
    if(encode) _file->encode(_key, chainingMethod, _iv, &padding, false, meta);


}

void Utils::generateRandomBinaryFile(const std::string& path, size_t size) {
    std::ofstream file(path, std::ios::binary);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < size; ++i) {
        char byte = static_cast<char>(dis(gen));
        file.put(byte);
    }

    file.close();
}

std::string Utils::generateRandomIV(){
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dis(0, 255);

    std::ostringstream oss;

    for (size_t i = 0; i < 16; ++i) {
        unsigned int byte = dis(gen);
        oss << std::hex << std::setw(2) << std::setfill('0') << byte;
    }

    return oss.str();
}


}