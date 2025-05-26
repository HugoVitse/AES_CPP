#pragma once
#include <stdexcept>
#include <string>

namespace AES_CPP {

class FileException : public std::runtime_error {
    
public:
    explicit FileException(const std::string& message)
        : std::runtime_error(message) {}
};

}
