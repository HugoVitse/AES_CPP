# AES File Encryptor/Decryptor (ECB & CBC) – C++

A C++ implementation of the **AES (Advanced Encryption Standard)** algorithm, supporting both **ECB (Electronic Codebook)** and **CBC (Cipher Block Chaining)** modes. It includes support for **PKCS#7** and **Zero Padding**.

## Features

- AES-128, 192, 256 encryption and decryption
- ECB and CBC modes supported
- PKCS#7 and Zero Padding implemented
- Minimal external dependencies (standard C++17)

## Compilation requirements

- C++17-compatible compiler
- CMake >= 3.10
- Boost (program_options) – for command-line argument parsing
- GoogleTest – for unit testing


## Compilation

```bash
mkdir build
cd build
cmake ..
cd ..
cmake --build build
```

## Usage

```bash
./AES_CPP --file <filepath> (mandatory)
          --key <key> (mandatory)
          --iv <iv>
          --chaining <CBC|ECB>
          --padding <PKCS7|ZERO>
          --output <output filepath>
          --decode
          --encode

```

