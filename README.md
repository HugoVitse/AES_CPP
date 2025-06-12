# AES File Encryptor/Decryptor (ECB, CBC, CTR, GCM) – C++

A C++ implementation of the **AES (Advanced Encryption Standard)** algorithm, supporting **ECB (Electronic Codebook)** , **CBC (Cipher Block Chaining)** , **CTR (Counter)** and **GCM (Galois Counter Mode)** modes. It includes support for **PKCS#7** and **Zero Padding**.

## Features

- AES-128, 192, 256 encryption and decryption
- ECB, CBC, CTR and GCM modes supported
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

### Encryption

```bash
./AES_CPP --file <filepath> (mandatory)
          --key <key> (mandatory)
          --iv <iv> (randomly generated if not set)
          --chaining <CBC|ECB|CTR|GCM> (default : CBC)
          --padding <PKCS7|ZERO> (default : PKCS7)
          --output <output filepath> (encrypt the source file directly if not set)
          --encode

```

### Decryption

```bash
./AES_CPP --file <filepath> (mandatory)
          --key <key> (mandatory)
          --output <output filepath> (decrypt the source file directly if not set)
          --decode

```

