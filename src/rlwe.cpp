#include "polynomial.h"
#include <rlwe.h>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <limits>
#include <random>
#include <sstream>
#include <sha256.h>

static void getSecureRandomBytes(uint8_t* buffer, size_t length) {
    std::random_device rd("/dev/urandom");
    if (!rd.entropy()) {
        throw std::runtime_error("Failed to access secure random source");
    }
    
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
      a(n, q),
      b(n, q),
      s(n, q)
{
    Logger::log("Created RLWE instance with n=" + std::to_string(n) + 
                ", q=" + std::to_string(q));
}

void RLWESignature::generateKeys() {
    Logger::log("\nGenerating keys...");
    
    Logger::log("Sampling uniform polynomial a");
    a = sampleUniform();
    
    Logger::log("Sampling gaussian polynomial s (secret key)");
    s = sampleGaussian(GAUSSIAN_STDDEV);
    
    Logger::log("Sampling gaussian polynomial e");
    Polynomial e = sampleGaussian(GAUSSIAN_STDDEV);
    
    Logger::log("Computing b = a*s + e");
    b = a * s + e;
    
    Logger::log("Key generation complete");
}

Polynomial RLWESignature::blindSign(const Polynomial& blindedMessagePoly) {
    const Polynomial& z = blindedMessagePoly; 
    Polynomial e1 = sampleGaussian(GAUSSIAN_STDDEV);
    Polynomial u = s * z + e1;
    
    return u;
}

bool RLWESignature::verify(const std::vector<uint8_t>& message,
                          const Polynomial& signature) {
    logMessageBytes("Message", message);
    
    const auto& u = signature;
    Logger::log("Signature:\n  u: " + u.toString());
    
    Logger::log("Hashing secret to polynomial");
    Polynomial z = hashToPolynomial(message);
    Logger::log("Message polynomial z: " + z.toString());
    
    Logger::log("Computing c = s * z");
    Polynomial c = s * z;
    Logger::log("c (before rounding): " + c.toString());
    
    uint64_t q_half = modulus / 2;
    Logger::log("Computing expected = floor(q/2)*z with q/2 = " + std::to_string(q_half));
    Polynomial expected = z * q_half;
    Logger::log("Expected (before rounding): " + expected.toString());

    // Round both polynomials to binary signals (0 or q/2)
    Polynomial actual_signal = c.polySignal();
    Polynomial expected_signal = u.polySignal();
    
    Logger::log("Actual (after rounding): " + actual_signal.toString());
    Logger::log("Expected (after rounding): " + expected_signal.toString());

    // Compare the coefficients
    const auto& actual_coeffs = actual_signal.getCoeffs();
    const auto& expected_coeffs = expected_signal.getCoeffs();
    
    bool result = true;
    for (size_t i = 0; i < actual_coeffs.size(); i++) {
        if (actual_coeffs[i] != expected_coeffs[i]) {
            Logger::log("Mismatch at coefficient " + std::to_string(i) + 
                       ": actual=" + std::to_string(actual_coeffs[i]) + 
                       ", expected=" + std::to_string(expected_coeffs[i]));
            result = false;
            break;
        }
    }
    
    Logger::log("Verification result: " + std::string(result ? "true" : "false"));
    return result;
}

std::pair<Polynomial, Polynomial> RLWESignature::computeBlindedMessage(const std::vector<uint8_t>& secret) {
    Polynomial r = sampleUniform();
    Polynomial Y = hashToPolynomial(secret);
    return std::make_pair(Y + r, r);
}

Polynomial RLWESignature::computeSignature(
    const Polynomial& blindSignature,
    const Polynomial& blindingFactor,
    const Polynomial& publicKey
) {
    const auto& C_ = blindSignature;
    const auto& r = blindingFactor;
    const auto& A = publicKey;
    return C_ - r*A;
}

Polynomial RLWESignature::sampleUniform() {
    std::vector<uint64_t> coeffs(ring_dim_n);
    
    for (size_t i = 0; i < ring_dim_n; i++) {
        coeffs[i] = getRandomUint64() % modulus;
    }
    
    return Polynomial(coeffs, modulus);
}

Polynomial RLWESignature::sampleGaussian(double stddev) {
    std::vector<uint64_t> coeffs(ring_dim_n);
    
    for (size_t i = 0; i < ring_dim_n; i++) {
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
    std::vector<uint64_t> coeffs(ring_dim_n, 0);
    
    // Print debug info about message bits
    Logger::log("Message bits:");
    for (size_t byte_idx = 0; byte_idx < message.size(); byte_idx++) {
        std::stringstream ss;
        ss << "Byte " << byte_idx << ": ";
        for (int j = 7; j >= 0; j--) {
            ss << ((message[byte_idx] >> j) & 1);
        }
        Logger::log(ss.str());
    }
    
    // Process each byte separately, starting from most significant bit
    size_t coeff_idx = 0;
    for (size_t byte_idx = 0; byte_idx < message.size() && coeff_idx < ring_dim_n; byte_idx++) {
        uint8_t byte = message[byte_idx];
        // Process bits in MSB to LSB order
        for (int j = 7; j >= 0 && coeff_idx < ring_dim_n; j--) {
            coeffs[coeff_idx++] = (byte >> j) & 1;
        }
    }
    
    // Print encoded coefficients
    Logger::log("Encoded coefficients: " + Logger::vectorToString(coeffs));
    
    return Polynomial(coeffs, modulus);
}

Polynomial RLWESignature::hashToPolynomial(const std::vector<uint8_t>& message) {
    // Create a polynomial to hold the result
    std::vector<uint64_t> coeffs(ring_dim_n, 0);
    
    Logger::log("Converting message to polynomial using counter-based hashing");
    
    // Process message in blocks using counter
    size_t coeff_idx = 0;
    uint32_t counter = 0;
    
    while (coeff_idx < ring_dim_n) {
        // Prepare message block with counter
        std::vector<uint8_t> block;
        block.reserve(message.size() + sizeof(counter));
        
        // Add counter to the beginning of the block
        const uint8_t* counter_bytes = reinterpret_cast<const uint8_t*>(&counter);
        block.insert(block.end(), counter_bytes, counter_bytes + sizeof(counter));
        
        // Add original message
        block.insert(block.end(), message.begin(), message.end());
        
        // Hash the block
        std::vector<uint8_t> hash = SHA256::hash(block);
        Logger::log("Block " + std::to_string(counter) + " hash: " + Logger::vectorToString(hash));
        
        // Convert hash bits to coefficients
        for (size_t byte_idx = 0; coeff_idx < ring_dim_n && byte_idx < hash.size(); byte_idx++) {
            for (int bit = 7; bit >= 0 && coeff_idx < ring_dim_n; bit--) {
                bool bit_value = (hash[byte_idx] >> bit) & 1;
                coeffs[coeff_idx++] = bit_value ? (modulus / 2) : 0;
            }
        }
        
        counter++;
    }
    
    Logger::log("Final polynomial coefficients: " + Logger::vectorToString(coeffs));
    return Polynomial(coeffs, modulus);
}
