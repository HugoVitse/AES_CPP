#pragma once
#include <stdexcept>
#include <string>

namespace AES_CPP {

class UtilException : public std::runtime_error {
    
public:
    explicit UtilException(const std::string& message)
        : std::runtime_error(message) {}
};

}
