#include "polynomial.h"
#include <algorithm>
#include <stdexcept>

Polynomial Polynomial::operator+(const Polynomial& other) const {
    if (ring_dim != other.ring_dim || modulus != other.modulus) {
        throw std::invalid_argument("Polynomials must be in the same ring");
    }

    Polynomial result(ring_dim, modulus);
    for (size_t i = 0; i < ring_dim; i++) {
        result[i] = (coeffs[i] + other.coeffs[i]) % modulus;
    }
    return result;
}

Polynomial Polynomial::operator-(const Polynomial& other) const {
    if (ring_dim != other.ring_dim || modulus != other.modulus) {
        throw std::invalid_argument("Polynomials must be in the same ring");
    }

    Polynomial result(ring_dim, modulus);
    for (size_t i = 0; i < ring_dim; i++) {
        result[i] = mod(static_cast<int64_t>(coeffs[i]) - 
                       static_cast<int64_t>(other.coeffs[i]), modulus);
    }
    return result;
}

Polynomial Polynomial::operator-() const {
    Polynomial result(ring_dim, modulus);
    for (size_t i = 0; i < ring_dim; i++) {
        result[i] = (coeffs[i] == 0) ? 0 : modulus - coeffs[i];
    }
    return result;
}

Polynomial Polynomial::operator*(const Polynomial& other) const {
    if (ring_dim != other.ring_dim || modulus != other.modulus) {
        throw std::invalid_argument("Polynomials must be in the same ring");
    }

    // Create temporary vector for the result with double size to hold intermediate values
    std::vector<uint64_t> temp(2 * ring_dim, 0);

    // Perform polynomial multiplication
    for (size_t i = 0; i < ring_dim; i++) {
        for (size_t j = 0; j < ring_dim; j++) {
            // Multiply coefficients and add to the appropriate position
            uint64_t prod = (static_cast<uint64_t>(coeffs[i]) * 
                           static_cast<uint64_t>(other.coeffs[j])) % modulus;
            temp[i + j] = (temp[i + j] + prod) % modulus;
        }
    }

    // Reduce modulo x^(2n) + 1
    Polynomial result(ring_dim, modulus);
    for (size_t i = 0; i < ring_dim; i++) {
        // Add the coefficient at position i
        result[i] = temp[i];
        
        // If there's a corresponding term of degree ≥ 2n,
        // subtract it (because x^(2n) = -1 in our ring)
        if (i + ring_dim < 2 * ring_dim) {
            result[i] = mod(static_cast<int64_t>(result[i]) - 
                          static_cast<int64_t>(temp[i + ring_dim]), modulus);
        }
    }

    return result;
}

Polynomial Polynomial::operator*(uint64_t scalar) const {
    Polynomial result(ring_dim, modulus);
    for (size_t i = 0; i < ring_dim; i++) {
        result[i] = (coeffs[i] * scalar) % modulus;
    }
    return result;
}
