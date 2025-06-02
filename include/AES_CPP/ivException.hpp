#pragma once
#include <stdexcept>
#include <string>

namespace AES_CPP {

class IVException : public std::runtime_error {
    
public:
    explicit IVException(const std::string& message)
        : std::runtime_error(message) {}
};

}
