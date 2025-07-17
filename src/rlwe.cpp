#include <rlwe.h>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <limits>
#include <random>
#include <sstream>

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
      a(2*n, q),
      b(2*n, q),
      s(2*n, q)
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

std::pair<Polynomial, Polynomial> RLWESignature::sign(const std::vector<uint8_t>& message) {
    Logger::log("\nSigning message");
    logMessageBytes("Message", message);
    
    Logger::log("Converting message to polynomial");
    Polynomial z = messageToPolynomial(message);
    
    Logger::log("Sampling gaussian polynomials r, e1, e2");
    Polynomial r = sampleGaussian(GAUSSIAN_STDDEV);
    Polynomial e1 = sampleGaussian(GAUSSIAN_STDDEV);
    Polynomial e2 = sampleGaussian(GAUSSIAN_STDDEV);
    
    Logger::log("Computing u = a*r + e1");
    Polynomial u = a * r + e1;
    
    uint64_t q_half = modulus / 2;
    Logger::log("Computing v = b*r + e2 + floor(q/2)*z with q/2 = " + 
                std::to_string(q_half));
    Polynomial v = b * r + e2 + z * q_half;
    
    Logger::log("Signature complete");
    return std::make_pair(u, v);
}

bool RLWESignature::verify(const std::vector<uint8_t>& message,
                          const std::pair<Polynomial, Polynomial>& signature) {
    Logger::log("\nVerifying signature");
    logMessageBytes("Message", message);
    
    const auto& [u, v] = signature;
    Logger::log("Signature components:\n  u: " + u.toString() + "\n  v: " + v.toString());
    
    Logger::log("Converting message to polynomial");
    Polynomial z = messageToPolynomial(message);
    Logger::log("Message polynomial z: " + z.toString());
    
    Logger::log("Computing v - u*s");
    Polynomial actual = v - u * s;
    Logger::log("Actual (before rounding): " + actual.toString());
    
    uint64_t q_half = modulus / 2;
    Logger::log("Computing expected = floor(q/2)*z with q/2 = " + std::to_string(q_half));
    Polynomial expected = z * q_half;
    Logger::log("Expected (before rounding): " + expected.toString());

    // Round both polynomials to binary signals (0 or q/2)
    Polynomial actual_signal = actual.polySignal();
    Polynomial expected_signal = expected.polySignal();
    
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
    for (size_t byte_idx = 0; byte_idx < message.size() && coeff_idx < 2 * ring_dim_n; byte_idx++) {
        uint8_t byte = message[byte_idx];
        // Process bits in MSB to LSB order
        for (int j = 7; j >= 0 && coeff_idx < 2 * ring_dim_n; j--) {
            coeffs[coeff_idx++] = (byte >> j) & 1;
        }
    }
    
    // Print encoded coefficients
    Logger::log("Encoded coefficients: " + Logger::vectorToString(coeffs));
    
    return Polynomial(coeffs, modulus);
}
