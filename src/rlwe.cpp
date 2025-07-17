#include "rlwe.h"
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <limits>
#include <random>

// Helper function to get secure random bytes
static void getSecureRandomBytes(uint8_t* buffer, size_t length) {
    std::random_device rd("/dev/urandom");
    if (!rd.entropy()) {
        throw std::runtime_error("Failed to access secure random source");
    }
    
    // Fill buffer with random bytes
    for (size_t i = 0; i < length; i += sizeof(uint32_t)) {
        uint32_t random = rd();
        size_t remaining = std::min(sizeof(uint32_t), length - i);
        std::memcpy(buffer + i, &random, remaining);
    }
}

uint64_t RLWESignature::getRandomUint64() {
    uint64_t result;
    getSecureRandomBytes(reinterpret_cast<uint8_t*>(&result), sizeof(result));
    return result;
}

double RLWESignature::getRandomDouble() {
    uint64_t r1, r2;
    getSecureRandomBytes(reinterpret_cast<uint8_t*>(&r1), sizeof(r1));
    getSecureRandomBytes(reinterpret_cast<uint8_t*>(&r2), sizeof(r2));
    
    double u1 = static_cast<double>(r1) / std::numeric_limits<uint64_t>::max();
    double u2 = static_cast<double>(r2) / std::numeric_limits<uint64_t>::max();
    
    double radius = std::sqrt(-2 * std::log(u1));
    double theta = 2 * M_PI * u2;
    
    return radius * std::cos(theta);
}

RLWESignature::RLWESignature(size_t n, uint64_t q)
    : ring_dim_n(n),
      modulus(q),
      a(2*n, q),  // dimension is 2n for the ring Z[x]/(x^(2n) + 1)
      b(2*n, q),
      s(2*n, q)
{
}

void RLWESignature::generateKeys() {
    a = sampleUniform();
    s = sampleGaussian(GAUSSIAN_STDDEV);
    Polynomial e = sampleGaussian(GAUSSIAN_STDDEV);
    b = a * s + e;
}

std::pair<Polynomial, Polynomial> RLWESignature::sign(const std::vector<uint8_t>& message) {
    Polynomial z = messageToPolynomial(message);
    
    Polynomial r = sampleGaussian(SIGNATURE_STDDEV);
    Polynomial e1 = sampleGaussian(SIGNATURE_STDDEV);
    Polynomial e2 = sampleGaussian(SIGNATURE_STDDEV);
    
    Polynomial u = a * r + e1;
    
    uint64_t q_half = modulus / 2;
    Polynomial v = b * r + e2 + z * q_half;
    
    return std::make_pair(u, v);
}

bool RLWESignature::verify(const std::vector<uint8_t>& message,
                          const std::pair<Polynomial, Polynomial>& signature) {
    const auto& [u, v] = signature;
    Polynomial z = messageToPolynomial(message);
    
    Polynomial result = v - u * s;
    
    uint64_t q_half = modulus / 2;
    Polynomial expected = z * q_half;
    
    uint64_t threshold = modulus / 4;
    
    const auto& result_coeffs = result.getCoeffs();
    const auto& expected_coeffs = expected.getCoeffs();
    
    for (size_t i = 0; i < 2 * ring_dim_n; i++) {
        uint64_t diff = (result_coeffs[i] >= expected_coeffs[i]) ?
                       result_coeffs[i] - expected_coeffs[i] :
                       expected_coeffs[i] - result_coeffs[i];
        
        if (diff > threshold && diff < modulus - threshold) {
            return false;
        }
    }
    
    return true;
}

Polynomial RLWESignature::sampleUniform() {
    std::vector<uint64_t> coeffs(2 * ring_dim_n);
    
    for (size_t i = 0; i < 2 * ring_dim_n; i++) {
        coeffs[i] = getRandomUint64() % modulus;
    }
    
    return Polynomial(coeffs, modulus);
}

Polynomial RLWESignature::sampleGaussian(double stddev) {
    std::vector<uint64_t> coeffs(2 * ring_dim_n);
    
    for (size_t i = 0; i < 2 * ring_dim_n; i++) {
        double sample = getRandomDouble() * stddev;
        int64_t rounded = static_cast<int64_t>(std::round(sample));
        
        if (rounded < 0) {
            rounded += modulus;
        }
        
        coeffs[i] = rounded % modulus;
    }
    
    return Polynomial(coeffs, modulus);
}

Polynomial RLWESignature::messageToPolynomial(const std::vector<uint8_t>& message) {
    std::vector<uint64_t> coeffs(2 * ring_dim_n, 0);
    
    size_t bit_idx = 0;
    for (size_t byte_idx = 0; byte_idx < message.size() && bit_idx < 2 * ring_dim_n; byte_idx++) {
        uint8_t byte = message[byte_idx];
        for (size_t j = 0; j < 8 && bit_idx < 2 * ring_dim_n; j++, bit_idx++) {
            coeffs[bit_idx] = (byte >> j) & 1;
        }
    }
    
    return Polynomial(coeffs, modulus);
}
