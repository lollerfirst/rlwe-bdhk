#ifndef RLWE_H
#define RLWE_H

#include <vector>
#include <random>
#include <cstdint>

// Polynomial ring operations in Z[x]/(x^(2n) + 1)
class RLWESignature {
public:
    RLWESignature(size_t n, uint64_t q);
    
    // Key generation
    void generateKeys();
    
    // Signature operations
    std::vector<uint64_t> sign(const std::vector<uint8_t>& message);
    bool verify(const std::vector<uint8_t>& message, const std::vector<uint64_t>& signature);

private:
    // Ring dimension (n)
    size_t ring_dim;
    // Modulus (q)
    uint64_t modulus;
    
    // Key material
    std::vector<uint64_t> a;     // Public random polynomial
    std::vector<uint64_t> b;     // Public key component (a*s + e)
    std::vector<uint64_t> s;     // Secret key
    
    // Helper functions
    std::vector<uint64_t> sampleUniform();
    std::vector<uint64_t> sampleGaussian(double stddev);
    std::vector<uint64_t> polynomialMul(const std::vector<uint64_t>& p1, 
                                       const std::vector<uint64_t>& p2);
};

#endif // RLWE_H
