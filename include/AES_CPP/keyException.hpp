#pragma once
#include <stdexcept>
#include <string>

namespace AES_CPP {

class KeyException : public std::runtime_error {
    
public:
    explicit KeyException(const std::string& message)
        : std::runtime_error(message) {}
};

}
