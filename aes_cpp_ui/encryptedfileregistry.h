#ifndef ENCRYPTEDFILEREGISTRY_H
#define ENCRYPTEDFILEREGISTRY_H
#pragma once

#include <string>
#include <vector>


class EncryptedFileRegistry {
public:
    EncryptedFileRegistry();

    void addFile(const std::string& filePath);
    bool removeFile(const std::string& filePath);

    std::vector<std::string> getAllFiles() const;
    bool contains(const std::string& filePath) const;
    void clear();

private:
    std::string registryPath;

    void ensureDirectoryExists() const;
};

#endif // ENCRYPTEDFILEREGISTRY_H
