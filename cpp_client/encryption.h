
#pragma once

#include <string>

// Forward declarations for encryption/decryption functions
// In a real project, you'd include OpenSSL, Crypto++ or similar.
namespace Encryption {
    std::string encrypt_data(const std::string& plain_data, const std::string& key);
    std::string decrypt_data(const std::string& cipher_data, const std::string& key);
}