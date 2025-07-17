#ifndef RLWE_H
#define RLWE_H

#include "polynomial.h"
#include <vector>
#include <random>
#include <cstdint>
#include <memory>

class RLWESignature {
public:
    // Initialize with ring dimension n (degree will be 2n) and modulus q
    RLWESignature(size_t n, uint64_t q);
    
    // Generate keys: (a, b = a*s + e) as public key, s as private key
    void generateKeys();
    
    // Sign a message
    std::pair<Polynomial, Polynomial> sign(const std::vector<uint8_t>& message);
    
    // Verify a signature
    bool verify(const std::vector<uint8_t>& message, 
               const std::pair<Polynomial, Polynomial>& signature);

    // Get public key
    std::pair<Polynomial, Polynomial> getPublicKey() const {
        return std::make_pair(a, b);
    }

private:
    // Ring dimension (polynomial degree will be 2n)
    size_t ring_dim_n;
    // Modulus
    uint64_t modulus;
    
    // Random number generation
    std::mt19937_64 rng;
    
    // Public key components
    Polynomial a;  // Random polynomial
    Polynomial b;  // a*s + e
    
    // Private key
    Polynomial s;  // Secret key
    
    // Helper functions
    Polynomial sampleUniform();
    Polynomial sampleGaussian(double stddev);
    
    // Convert message to polynomial
    Polynomial messageToPolynomial(const std::vector<uint8_t>& message);
    
    // Parameters for Gaussian distribution
    static constexpr double GAUSSIAN_STDDEV = 3.0;
    static constexpr double SIGNATURE_STDDEV = 3.0;
};

#endif // RLWE_H
