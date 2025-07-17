#ifndef SHA256_H
#define SHA256_H

#include <vector>
#include <string>
#include <cstdint>
#include <openssl/evp.h>
#include "polynomial.h"

class SHA256 {
public:
    // Hash a vector of bytes
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data);
    
    // Hash a string
    static std::vector<uint8_t> hash(const std::string& data);
    
    // Hash a polynomial
    static std::vector<uint8_t> polyToHash(const Polynomial& poly);
    
    // Get the hash size in bytes (32 for SHA256)
    static constexpr size_t hashSize() { return EVP_MAX_MD_SIZE; }
    
private:
    // Helper to convert hash to byte vector
    static std::vector<uint8_t> digestToVector(const unsigned char* digest);
};

#endif // SHA256_H
