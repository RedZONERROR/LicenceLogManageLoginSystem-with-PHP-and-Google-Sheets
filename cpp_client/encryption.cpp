
#include "encryption.h"
#include <iostream>
#include <vector>
#include <algorithm> // For std::reverse
#include <string>
#include <cstdint>   // For uint8_t
#include <stdexcept>

// Minimal Base64 encoding/decoding for demonstration.
// For production, use a robust library.
namespace Base64 {
    const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

    std::string encode(const std::vector<uint8_t>& in) {
        std::string out;
        int val = 0, valb = -6;
        for (uint8_t c : in) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) {
            out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        while (out.size() % 4) {
            out.push_back('=');
        }
        return out;
    }

    std::vector<uint8_t> decode(const std::string& in) {
        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

        std::vector<uint8_t> out;
        int val = 0, valb = -8;
        for (char c : in) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                out.push_back(uint8_t((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }
} // namespace Base64

namespace Encryption {
    // These are *NOT* secure encryption implementations. They are placeholders.
    // Real encryption requires a secure library like OpenSSL or Crypto++.
    // For this demo, we'll just base64 encode/decode JSON strings.

    std::string encrypt_data(const std::string& plain_data, const std::string& key) {
        // In a real scenario, use AES with the 'key'.
        // For now, just base64 encode the string.
        std::vector<uint8_t> bytes(plain_data.begin(), plain_data.end());
        return Base64::encode(bytes);
    }

    std::string decrypt_data(const std::string& cipher_data, const std::string& key) {
        // In a real scenario, use AES with the 'key'.
        // For now, just base64 decode the string.
        std::vector<uint8_t> bytes = Base64::decode(cipher_data);
        return std::string(bytes.begin(), bytes.end());
    }
} // namespace Encryption