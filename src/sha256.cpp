#include <sha256.h>
#include <memory>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <stdexcept>

std::vector<uint8_t> SHA256::hash(const std::vector<uint8_t>& data) {
    // Create the EVP Message Digest Context
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> 
        mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    
    if (!mdctx) {
        throw std::runtime_error("Failed to create message digest context");
    }
    
    // Initialize with SHA256
    if (EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1) {
        throw std::runtime_error("Failed to initialize digest");
    }
    
    // Update with the data
    if (EVP_DigestUpdate(mdctx.get(), data.data(), data.size()) != 1) {
        throw std::runtime_error("Failed to update digest");
    }
    
    // Finalize
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    
    if (EVP_DigestFinal_ex(mdctx.get(), digest, &digest_len) != 1) {
        throw std::runtime_error("Failed to finalize digest");
    }
    
    return digestToVector(digest);
}

std::vector<uint8_t> SHA256::hash(const std::string& data) {
    return hash(std::vector<uint8_t>(data.begin(), data.end()));
}

std::vector<uint8_t> SHA256::polyToHash(const Polynomial& poly) {
    // Use the polynomial's toBytes method and hash the result
    return hash(poly.toBytes());
}

std::vector<uint8_t> SHA256::digestToVector(const unsigned char* digest) {
    return std::vector<uint8_t>(digest, digest + SHA256_DIGEST_LENGTH);
}
