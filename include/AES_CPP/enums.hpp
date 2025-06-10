#pragma once

namespace AES_CPP {

enum class ChainingMethod {
    CBC,
    ECB,
    CTR
};

enum class Padding {
    ZeroPadding,
    PKcs7,
    None
};

}