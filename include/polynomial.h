#ifndef POLYNOMIAL_H
#define POLYNOMIAL_H

#include <vector>
#include <cstdint>
#include <stdexcept>

class Polynomial {
public:
    // Constructor for polynomial in Z[x]/(x^(2n) + 1)
    Polynomial(size_t n, uint64_t q) : ring_dim(2*n), modulus(q) {
        coeffs.resize(ring_dim, 0);
    }

    // Constructor from coefficient vector
    Polynomial(const std::vector<uint64_t>& coefficients, uint64_t q) 
        : coeffs(coefficients), ring_dim(coefficients.size()), modulus(q) {}

    // Get coefficient at index
    uint64_t& operator[](size_t idx) {
        return coeffs[idx];
    }

    const uint64_t& operator[](size_t idx) const {
        return coeffs[idx];
    }

    // Get polynomial degree (2n)
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

    // Multiplication modulo (x^(2n) + 1) and q
    Polynomial operator*(const Polynomial& other) const;

    // Scalar multiplication modulo q
    Polynomial operator*(uint64_t scalar) const;

    // Get raw coefficients
    const std::vector<uint64_t>& getCoeffs() const {
        return coeffs;
    }

private:
    std::vector<uint64_t> coeffs;  // Coefficients
    size_t ring_dim;               // Polynomial ring dimension (2n)
    uint64_t modulus;              // Modulus q

    // Helper function for modular reduction
    static uint64_t mod(int64_t x, uint64_t m) {
        int64_t r = x % static_cast<int64_t>(m);
        return r < 0 ? r + m : r;
    }
};

#endif // POLYNOMIAL_H
