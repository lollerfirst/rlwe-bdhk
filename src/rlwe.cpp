#include <polynomial.h>
#include <rlwe.h>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <limits>
#include <random>
#include <sha256.h>

// Platform-specific includes for secure random
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#endif

static void getSecureRandomBytes(uint8_t* buffer, size_t length) {
#if defined(_WIN32)
    // Windows: Use BCrypt
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to open BCrypt algorithm provider");
    }
    
    status = BCryptGenRandom(hAlg, buffer, static_cast<ULONG>(length), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("Failed to generate random bytes using BCrypt");
    }
#elif defined(__APPLE__)
    // macOS: Use SecRandomCopyBytes
    if (SecRandomCopyBytes(kSecRandomDefault, length, buffer) != 0) {
        throw std::runtime_error("Failed to generate random bytes using SecRandomCopyBytes");
    }
#else
    // Linux and other Unix-like systems: Use /dev/urandom
    std::random_device rd("/dev/urandom");
    if (!rd.entropy()) {
        throw std::runtime_error("Failed to access secure random source");
    }
    
    for (size_t i = 0; i < length; i += sizeof(uint32_t)) {
        uint32_t random = rd();
        size_t remaining = std::min(sizeof(uint32_t), length - i);
        std::memcpy(buffer + i, &random, remaining);
    }
#endif
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

// Helper function to check if a number is a power of 2
static bool isPowerOfTwo(size_t n) {
    return n != 0 && (n & (n - 1)) == 0;
}

// Helper function to validate power of 2 using compiler intrinsics
static bool validatePowerOfTwo(size_t n) {
    if (!isPowerOfTwo(n)) {
        return false;
    }

#if defined(_MSC_VER) // Microsoft Visual C++
    unsigned long index;
    // BitScanReverse works on unsigned long
    _BitScanReverse(&index, static_cast<unsigned long>(n));
    return (static_cast<size_t>(1) << index) == n;
#elif defined(__GNUC__) || defined(__clang__) // GCC or Clang
    // __builtin_popcountll works with unsigned long long (64-bit)
    unsigned long long n_ull = static_cast<unsigned long long>(n);
    return __builtin_popcountll(n_ull) == 1;
#else
    // Generic implementation: count the number of set bits
    size_t count = 0;
    size_t temp = n;
    while (temp > 0) {
        count += temp & 1;
        temp >>= 1;
    }
    return count == 1;
#endif
}

RLWESignature::RLWESignature(size_t n, uint64_t q)
    : ring_dim_n(n),
      modulus(q),
      a(n, q),
      b(n, q),
      s(n, q)
{
    // Validate that n is a power of 2 using the helper function
    if (!validatePowerOfTwo(n)) {
        throw std::invalid_argument("n must be a power of 2");
    }

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
    
    Logger::log("Public key a: " + a.toString());
    Logger::log("Public key b: " + b.toString());  
    Logger::log("Secret key s: " + s.toString());
}

std::pair<Polynomial, Polynomial> RLWESignature::computeBlindedMessage(const std::vector<uint8_t>& secret) {
    Logger::log("\nComputing blinded message...");
    
    // Sample random blinding factor
    Polynomial r = sampleGaussian(GAUSSIAN_STDDEV);
    Logger::log("Random blinding factor r: " + r.toString());
    
    // Hash secret to polynomial
    Polynomial Y = hashToPolynomial(secret);
    Logger::log("Hashed secret Y: " + Y.toString());
    
    // Compute blinded message: Y + a*r    
    Polynomial blindedMessage = Y + a * r;
    Logger::log("Blinded message (Y + a*r): " + blindedMessage.toString());
    
    return std::make_pair(blindedMessage, r);
}

Polynomial RLWESignature::blindSign(const Polynomial& blindedMessagePoly) {
    Logger::log("\nPerforming blind signing...");
    Logger::log("Blinded message received: " + blindedMessagePoly.toString());
    
    Polynomial e1 = sampleGaussian(GAUSSIAN_STDDEV);

    // Compute signature: s * blinded_message
    Polynomial signature = s * blindedMessagePoly + e1;
    Logger::log("Computed blind signature (s * blinded_message): " + signature.toString());
    
    return signature;
}

bool RLWESignature::verify(const std::vector<uint8_t>& message,
                          const Polynomial& signature) {
    Logger::log("\nVerifying signature...");
    logMessageBytes("Message", message);
    Logger::log("Signature to verify: " + signature.toString());
    
    // Hash message to polynomial
    Polynomial z = hashToPolynomial(message);
    Logger::log("Hashed message z: " + z.toString());
    
    // Expected value: s * z
    Polynomial expected = s * z;
    Logger::log("Expected value (s*z): " + expected.toString());

    // Round both polynomials to binary signals (0 or q/2)
    Polynomial actual_signal = signature.polySignal();
    Polynomial expected_signal = expected.polySignal();
    
    Logger::log("Rounded signature: " + actual_signal.toString());
    Logger::log("Rounded expected: " + expected_signal.toString());

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
    
    Logger::log("Verification result: " + std::string(result ? "SUCCESS" : "FAILED"));
    return result;
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
    
    // Process each byte separately, starting from most significant bit
    size_t coeff_idx = 0;
    for (size_t byte_idx = 0; byte_idx < message.size() && coeff_idx < ring_dim_n; byte_idx++) {
        uint8_t byte = message[byte_idx];
        // Process bits in MSB to LSB order
        for (int j = 7; j >= 0 && coeff_idx < ring_dim_n; j--) {
            coeffs[coeff_idx++] = (byte >> j) & 1;
        }
    }
        
    return Polynomial(coeffs, modulus);
}

Polynomial RLWESignature::hashToPolynomial(const std::vector<uint8_t>& message) {
    Logger::log("\nConverting message to polynomial using counter-based hashing");
    logMessageBytes("Input message", message);
    
    // Create a polynomial to hold the result
    std::vector<uint64_t> coeffs(ring_dim_n, 0);
        
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
        
        Logger::log("Block " + std::to_string(counter) + " content:");
        logMessageBytes("  ", block);
        
        // Hash the block
        std::vector<uint8_t> hash = SHA256::hash(block);
        std::stringstream ss;
        ss << "Block " << counter << " hash: ";
        for (uint8_t b : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        Logger::log(ss.str());

        // Convert hash bits to coefficients
        for (size_t byte_idx = 0; coeff_idx < ring_dim_n && byte_idx < hash.size(); byte_idx++) {
            for (int bit = 7; bit >= 0 && coeff_idx < ring_dim_n; bit--) {
                bool bit_value = (hash[byte_idx] >> bit) & 1;
                coeffs[coeff_idx++] = bit_value ? (modulus / 2) : 0;
            }
        }
        
        counter++;
    }
    
    Logger::log("Final polynomial coefficients:");
    std::stringstream result_ss;
    for (size_t i = 0; i < coeffs.size(); i++) {
        if (i > 0) result_ss << ", ";
        result_ss << coeffs[i];
    }
    Logger::log(result_ss.str());
    
    return Polynomial(coeffs, modulus);
}
