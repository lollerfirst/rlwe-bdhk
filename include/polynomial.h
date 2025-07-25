#ifndef POLYNOMIAL_H
#define POLYNOMIAL_H

#include <vector>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <logging.h>

class Polynomial {
public:
    // Constructor for polynomial in Z[x]/(x^n + 1)
    Polynomial(size_t n, uint64_t q) : ring_dim(n), modulus(q) {
        coeffs.resize(ring_dim, 0);
        Logger::log("Created zero polynomial of degree " + std::to_string(n-1) + 
                   " with modulus " + std::to_string(q));
    }

    // Constructor from coefficient vector
    Polynomial(const std::vector<uint64_t>& coefficients, uint64_t q) 
        : coeffs(coefficients), ring_dim(coefficients.size()), modulus(q) {
        Logger::log("Created polynomial from coefficients: " + 
                   Logger::vectorToString(coefficients) +
                   " with modulus " + std::to_string(q));
    }

    // Get coefficient at index
    uint64_t& operator[](size_t idx) {
        return coeffs[idx];
    }

    const uint64_t& operator[](size_t idx) const {
        return coeffs[idx];
    }

    // Get polynomial degree
    size_t degree() const {
        return ring_dim;
    }

    // Get modulus
    uint64_t getModulus() const {
        return modulus;
    }

    // Addition modulo q
    Polynomial operator+(const Polynomial& other) const;

    // Subtraction modulo q
    Polynomial operator-(const Polynomial& other) const;

    // Negation modulo q
    Polynomial operator-() const;

    // Multiplication modulo (x^n + 1) and q
    Polynomial operator*(const Polynomial& other) const;

    // Scalar multiplication modulo q
    Polynomial operator*(uint64_t scalar) const;

    // Get raw coefficients
    const std::vector<uint64_t>& getCoeffs() const {
        return coeffs;
    }

    // Round coefficients to either 0 or q/2 (whichever is closer)
    Polynomial polySignal() const;

    // Set polynomial coefficients
    void setCoefficients(const std::vector<uint64_t>& new_coeffs) {
        if (new_coeffs.size() != ring_dim) {
            throw std::invalid_argument("New coefficient vector size must match polynomial ring dimension");
        }
        coeffs = new_coeffs;
        // Reduce each coefficient modulo q
        for (auto& c : coeffs) {
            c = mod(c, modulus);
        }
        Logger::log("Updated polynomial coefficients to: " + Logger::vectorToString(coeffs));
    }

    // Convert to string for logging
    std::string toString() const {
        std::stringstream ss;
        ss << "Polynomial(dim=" << ring_dim << ", q=" << modulus << "): ";
        ss << Logger::vectorToString(coeffs);
        return ss.str();
    }

    // Convert polynomial to bytes
    std::vector<uint8_t> toBytes() const {
        std::vector<uint8_t> bytes;
        
        // Reserve space for metadata + coefficients
        bytes.reserve(2 * sizeof(uint64_t) + coeffs.size() * sizeof(uint64_t));
        
        // Add ring dimension
        const uint8_t* dim_bytes = reinterpret_cast<const uint8_t*>(&ring_dim);
        bytes.insert(bytes.end(), dim_bytes, dim_bytes + sizeof(size_t));
        
        // Add modulus
        const uint8_t* mod_bytes = reinterpret_cast<const uint8_t*>(&modulus);
        bytes.insert(bytes.end(), mod_bytes, mod_bytes + sizeof(uint64_t));
        
        // Add coefficients
        for (const uint64_t& coeff : coeffs) {
            const uint8_t* coeff_bytes = reinterpret_cast<const uint8_t*>(&coeff);
            bytes.insert(bytes.end(), coeff_bytes, coeff_bytes + sizeof(uint64_t));
        }
        
        return bytes;
    }

private:
    std::vector<uint64_t> coeffs;  // Coefficients
    size_t ring_dim;               // Polynomial ring dimension
    uint64_t modulus;              // Modulus q

    // Helper function for modular reduction
    static uint64_t mod(int64_t x, uint64_t m) {
        int64_t r = x % static_cast<int64_t>(m);
        return r < 0 ? r + m : r;
    }
};

#endif // POLYNOMIAL_H
