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
    Polynomial result = v - u * s;
    Logger::log("Result: " + result.toString());
    
    uint64_t q_half = modulus / 2;
    Logger::log("Computing expected = floor(q/2)*z with q/2 = " + std::to_string(q_half));
    Polynomial expected = z * q_half;
    Logger::log("Expected: " + expected.toString());
    
    Logger::log("Using thresholds:");
    //uint64_t small_threshold = static_cast<uint64_t>(modulus / SMALL_THRESHOLD_DIVISOR);
    uint64_t large_threshold = static_cast<uint64_t>(modulus / LARGE_THRESHOLD_DIVISOR);
    // Logger::log("  For values near 0: q/" + std::to_string(SMALL_THRESHOLD_DIVISOR) + 
                //" = " + std::to_string(small_threshold));
    Logger::log("  For values near q/2: q/" + std::to_string(LARGE_THRESHOLD_DIVISOR) + 
                " = " + std::to_string(large_threshold));
    
    const auto& result_coeffs = result.getCoeffs();
    const auto& expected_coeffs = expected.getCoeffs();
    
    size_t significant_differences = 0;
    
    for (size_t i = 0; i < 2 * ring_dim_n; i++) {
        bool is_significant = isValueSignificantlyDifferent(result_coeffs[i], expected_coeffs[i]);
        
        // Detailed logging for better debugging
        std::string significance = expected_coeffs[i] == 0 ? 
            "near 0" : "near q/2";
        uint64_t dist = getCyclicDistance(result_coeffs[i], expected_coeffs[i]);
        uint64_t used_threshold = large_threshold;
        
        Logger::log(std::string("Coefficient ") + std::to_string(i) + 
                   ": result=" + std::to_string(result_coeffs[i]) +
                   ", expected=" + std::to_string(expected_coeffs[i]) +
                   " (" + significance + ")" +
                   ", distance=" + std::to_string(dist) +
                   ", threshold=" + std::to_string(used_threshold) +
                   ", significant=" + (is_significant ? "true" : "false"));
        
        if (is_significant) {
            Logger::log("Significant difference found at index " + std::to_string(i));
            significant_differences++;
        }
    }
    
    bool valid = significant_differences < MIN_DIFFERENT_COEFFS;
    Logger::log("Found " + std::to_string(significant_differences) + 
                " significant differences");
    Logger::log("Minimum differences for invalid signature: " + 
                std::to_string(MIN_DIFFERENT_COEFFS));
    Logger::log("Verification result: " + std::string(valid ? "valid" : "invalid"));
    return valid;
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
