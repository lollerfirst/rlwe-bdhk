#ifndef RLWE_H
#define RLWE_H

#include <cmath>
#include <polynomial.h>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <logging.h>

class RLWESignature {
public:
    RLWESignature(size_t n, uint64_t q);
    void generateKeys();
    std::pair<Polynomial, Polynomial> sign(const std::vector<uint8_t>& message);
    bool verify(const std::vector<uint8_t>& message, 
               const std::pair<Polynomial, Polynomial>& signature);

    std::pair<Polynomial, Polynomial> getPublicKey() const {
        return std::make_pair(a, b);
    }

private:
    size_t ring_dim_n;
    uint64_t modulus;
    
    // Public key components
    Polynomial a;  // Random polynomial
    Polynomial b;  // a*s + e
    
    // Private key
    Polynomial s;  // Secret key
    
    // Helper functions
    uint64_t getRandomUint64();
    double getRandomDouble();
    Polynomial sampleUniform();
    Polynomial sampleGaussian(double stddev);
    Polynomial messageToPolynomial(const std::vector<uint8_t>& message);
    
    // Reduced standard deviation for better sensitivity
    static constexpr double GAUSSIAN_STDDEV = 3.0;     // Small standard deviation for cleaner signals
    
    // Verification parameters
    static constexpr double LARGE_THRESHOLD_DIVISOR = 4.0;   // For values near q/2
    static constexpr size_t MIN_DIFFERENT_COEFFS = 1;       // Even a single significant difference is meaningful

    // Helper to calculate cyclic distance between two values
    uint64_t getCyclicDistance(uint64_t a, uint64_t b) const {
        uint64_t direct = (a >= b) ? a - b : b - a;
        uint64_t wrap = modulus - direct;
        return std::min(direct, wrap);
    }

    // Helper for verification
    bool isValueSignificantlyDifferent(uint64_t value, uint64_t expected) const {
        uint64_t dist = getCyclicDistance(value, expected);
        
        // For q/2 check, we want a larger threshold since these are our message bits
        return dist > floor(modulus / LARGE_THRESHOLD_DIVISOR);
    }

    // Logging helper
    void logMessageBytes(const std::string& prefix, const std::vector<uint8_t>& message) {
        std::stringstream ss;
        ss << prefix << " bytes: [";
        for (size_t i = 0; i < message.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') 
               << static_cast<int>(message[i]);
        }
        ss << "]";
        Logger::log(ss.str());
    }
};

#endif // RLWE_H
