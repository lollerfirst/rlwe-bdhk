#include "rlwe.h"
#include <chrono>
#include <cmath>

RLWESignature::RLWESignature(size_t n, uint64_t q)
    : ring_dim_n(n),
      modulus(q),
      // Initialize polynomials with degree 2n
      a(2*n, q),
      b(2*n, q),
      s(2*n, q)
{
    // Seed RNG with current time
    auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    rng.seed(seed);
}

void RLWESignature::generateKeys() {
    // Generate uniform random polynomial a
    a = sampleUniform();
    
    // Generate small polynomials s and e from Gaussian distribution
    s = sampleGaussian(GAUSSIAN_STDDEV);
    Polynomial e = sampleGaussian(GAUSSIAN_STDDEV);
    
    // Compute b = a*s + e
    b = a * s + e;
}

std::pair<Polynomial, Polynomial> RLWESignature::sign(const std::vector<uint8_t>& message) {
    // Convert message to polynomial
    Polynomial z = messageToPolynomial(message);
    
    // Sample random small polynomials
    Polynomial r = sampleGaussian(SIGNATURE_STDDEV);
    Polynomial e1 = sampleGaussian(SIGNATURE_STDDEV);
    Polynomial e2 = sampleGaussian(SIGNATURE_STDDEV);
    
    // Calculate u = a*r + e1
    Polynomial u = a * r + e1;
    
    // Calculate floor(q/2)
    uint64_t q_half = modulus / 2;
    
    // Calculate v = b*r + e2 + floor(q/2)*z
    Polynomial v = b * r + e2 + z * q_half;
    
    return std::make_pair(u, v);
}

bool RLWESignature::verify(const std::vector<uint8_t>& message,
                          const std::pair<Polynomial, Polynomial>& signature) {
    const auto& [u, v] = signature;
    
    // Convert message to polynomial
    Polynomial z = messageToPolynomial(message);
    
    // Calculate v - u*s
    Polynomial result = v - u * s;
    
    // Calculate floor(q/2)
    uint64_t q_half = modulus / 2;
    Polynomial expected = z * q_half;
    
    // Check if the coefficients are close enough
    // We consider them close if their difference is less than q/4
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
    std::uniform_int_distribution<uint64_t> dist(0, modulus - 1);
    Polynomial result(2 * ring_dim_n, modulus);
    
    for (size_t i = 0; i < 2 * ring_dim_n; i++) {
        result[i] = dist(rng);
    }
    
    return result;
}

Polynomial RLWESignature::sampleGaussian(double stddev) {
    std::normal_distribution<double> dist(0.0, stddev);
    Polynomial result(2 * ring_dim_n, modulus);
    
    for (size_t i = 0; i < 2 * ring_dim_n; i++) {
        // Sample from Gaussian and round to nearest integer
        double sample = dist(rng);
        int64_t rounded = static_cast<int64_t>(std::round(sample));
        
        // Convert to positive modulus if negative
        if (rounded < 0) {
            rounded += modulus;
        }
        
        result[i] = rounded % modulus;
    }
    
    return result;
}

Polynomial RLWESignature::messageToPolynomial(const std::vector<uint8_t>& message) {
    Polynomial result(2 * ring_dim_n, modulus);
    
    // Use each bit of the message as a coefficient (0 or 1)
    size_t bit_idx = 0;
    for (size_t byte_idx = 0; byte_idx < message.size() && bit_idx < 2 * ring_dim_n; byte_idx++) {
        uint8_t byte = message[byte_idx];
        for (size_t j = 0; j < 8 && bit_idx < 2 * ring_dim_n; j++, bit_idx++) {
            result[bit_idx] = (byte >> j) & 1;
        }
    }
    
    return result;
}
