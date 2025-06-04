#pragma once

namespace AES_CPP {

enum class ChainingMethod {
    CBC,
    EBC
};

enum class Padding {
    ZeroPadding,
    PKcs7,
    None
};

}