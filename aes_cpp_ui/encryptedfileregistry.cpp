#include "encryptedfileregistry.h"

#include <fstream>
#include <filesystem>
#include <cstdlib> // getenv
#include <iostream>

EncryptedFileRegistry::EncryptedFileRegistry() {
    const char* home = std::getenv("HOME");
    if (!home) {
        throw std::runtime_error("HOME environment variable not set.");
    }

    registryPath = std::string(home) + "/.config/aes_cpp/encrypted_files.txt";
    ensureDirectoryExists();
}

void EncryptedFileRegistry::ensureDirectoryExists() const {
    std::filesystem::create_directories(std::filesystem::path(registryPath).parent_path());
}

void EncryptedFileRegistry::addFile(const std::string& filePath) {
    if (!contains(filePath)) {
        std::ofstream out(registryPath, std::ios::app);
        if (out.is_open()) {
            out << filePath << '\n';
        }
    }
}

bool EncryptedFileRegistry::removeFile(const std::string& filePath) {
    std::vector<std::string> files = getAllFiles();
    bool found = false;

    std::ofstream out(registryPath, std::ios::trunc);  // on écrase le fichier
    if (!out.is_open()) return false;

    for (const auto& f : files) {
        if (f != filePath) {
            out << f << '\n';
        } else {
            found = true;
        }
    }

    return found;
}


std::vector<std::string> EncryptedFileRegistry::getAllFiles() const {
    std::vector<std::string> files;
    std::ifstream in(registryPath);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) {
            files.push_back(line);
        }
    }
    return files;
}

bool EncryptedFileRegistry::contains(const std::string& filePath) const {
    std::ifstream in(registryPath);
    std::string line;
    while (std::getline(in, line)) {
        if (line == filePath) return true;
    }
    return false;
}

void EncryptedFileRegistry::clear() {
    std::ofstream out(registryPath, std::ios::trunc); // truncate
}
