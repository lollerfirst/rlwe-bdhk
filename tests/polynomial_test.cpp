#include <gtest/gtest.h>
#include <polynomial.h>

class PolynomialTest : public ::testing::Test {
protected:
    // Using parameters for easier testing
    // Z[x]/(x^4 + 1) mod 17
    const size_t n = 2;  // degree will be 2n = 4
    const uint64_t q = 17;
};

TEST_F(PolynomialTest, ToBytes) {
    // Create a polynomial
    Polynomial p(4, 17);
    std::vector<uint64_t> coeffs = {1, 2, 3, 4};
    p.setCoefficients(coeffs);
    
    // Get bytes
    auto bytes = p.toBytes();
    
    // Expected size: sizeof(size_t) for ring_dim + sizeof(uint64_t) for modulus + 
    // 4 * sizeof(uint64_t) for coefficients
    size_t expected_size = sizeof(size_t) + sizeof(uint64_t) + 4 * sizeof(uint64_t);
    EXPECT_EQ(bytes.size(), expected_size);
    
    // Create another identical polynomial
    Polynomial p2(4, 17);
    p2.setCoefficients(coeffs);
    
    // Verify that identical polynomials produce identical byte sequences
    EXPECT_EQ(p.toBytes(), p2.toBytes());
    
    // Modify one coefficient
    std::vector<uint64_t> coeffs2 = {1, 2, 3, 5};
    p2.setCoefficients(coeffs2);
    
    // Verify that different polynomials produce different byte sequences
    EXPECT_NE(p.toBytes(), p2.toBytes());
}

TEST_F(PolynomialTest, Addition) {
    // Create polynomials: f = 1 + 2x + 3x^2 + 4x^3, g = 5 + 6x + 7x^2 + 8x^3
    Polynomial f({1, 2, 3, 4}, q);
    Polynomial g({5, 6, 7, 8}, q);
    
    // Expected: (1+5) + (2+6)x + (3+7)x^2 + (4+8)x^3 mod 17
    // = 6 + 8x + 10x^2 + 12x^3
    Polynomial h = f + g;
    
    EXPECT_EQ(h[0], 6);
    EXPECT_EQ(h[1], 8);
    EXPECT_EQ(h[2], 10);
    EXPECT_EQ(h[3], 12);
}

// Rest of the test file...
