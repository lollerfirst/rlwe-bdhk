#include <gtest/gtest.h>
#include <polynomial.h>

class PolynomialTest : public ::testing::Test {
protected:
    // Will be used as Z[x]/(x^4 + 1) mod 17
    const size_t n = 2;  // degree will be 2n = 4
    const uint64_t q = 17;
};

TEST_F(PolynomialTest, SetCoefficients) {
    // Create zero polynomial
    Polynomial f(4, q);
    
    // Set coefficients and verify they are properly set with modular reduction
    std::vector<uint64_t> coeffs = {20, 21, 22, 23};  // These will be reduced mod 17
    f.setCoefficients(coeffs);
    
    // Check coefficients are correctly reduced mod 17
    EXPECT_EQ(f[0], 3);  // 20 mod 17 = 3
    EXPECT_EQ(f[1], 4);  // 21 mod 17 = 4
    EXPECT_EQ(f[2], 5);  // 22 mod 17 = 5
    EXPECT_EQ(f[3], 6);  // 23 mod 17 = 6
    
    // Test setting with values already reduced
    std::vector<uint64_t> coeffs2 = {1, 2, 3, 4};
    f.setCoefficients(coeffs2);
    
    EXPECT_EQ(f[0], 1);
    EXPECT_EQ(f[1], 2);
    EXPECT_EQ(f[2], 3);
    EXPECT_EQ(f[3], 4);
    
    // Test that invalid size throws exception
    std::vector<uint64_t> invalid_coeffs = {1, 2, 3};  // Wrong size
    EXPECT_THROW(f.setCoefficients(invalid_coeffs), std::invalid_argument);
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

TEST_F(PolynomialTest, Multiplication) {
    // Create polynomials: f = 1 + x, g = 1 + x
    Polynomial f({1, 1, 0, 0}, q);
    Polynomial g({1, 1, 0, 0}, q);
    
    // Expected: (1 + x)(1 + x) = 1 + 2x + x^2
    // In Z[x]/(x^4 + 1), this is just 1 + 2x + x^2
    Polynomial h = f * g;
    
    EXPECT_EQ(h[0], 1);
    EXPECT_EQ(h[1], 2);
    EXPECT_EQ(h[2], 1);
    EXPECT_EQ(h[3], 0);
}

TEST_F(PolynomialTest, Negation) {
    // Create polynomial f = 1 + 2x + 3x^2 + 4x^3
    Polynomial f({1, 2, 3, 4}, q);
    
    // Expected: 16 + 15x + 14x^2 + 13x^3 (negatives modulo 17)
    Polynomial g = -f;
    
    EXPECT_EQ(g[0], 16);
    EXPECT_EQ(g[1], 15);
    EXPECT_EQ(g[2], 14);
    EXPECT_EQ(g[3], 13);
}

TEST_F(PolynomialTest, ScalarMultiplication) {
    // Create polynomial f = 1 + 2x + 3x^2 + 4x^3
    Polynomial f({1, 2, 3, 4}, q);
    
    // Multiply by 2
    Polynomial g = f * 2ULL;
    
    EXPECT_EQ(g[0], 2);
    EXPECT_EQ(g[1], 4);
    EXPECT_EQ(g[2], 6);
    EXPECT_EQ(g[3], 8);
}

TEST_F(PolynomialTest, PolySignal) {
    // Using q = 17, so q/2 = 8
    Polynomial f(4, q);
    
    // Test case 1: Values close to 0
    std::vector<uint64_t> coeffs1 = {1, 2, 16, 15};  // 1,2 close to 0, 16,15 close to 0 (as -1,-2)
    f.setCoefficients(coeffs1);
    Polynomial signal1 = f.polySignal();
    
    EXPECT_EQ(signal1[0], 0);
    EXPECT_EQ(signal1[1], 0);
    EXPECT_EQ(signal1[2], 0);
    EXPECT_EQ(signal1[3], 0);
    
    // Test case 2: Values close to q/2 (8)
    std::vector<uint64_t> coeffs2 = {7, 8, 9, 10};  // All close to 8 (q/2)
    f.setCoefficients(coeffs2);
    Polynomial signal2 = f.polySignal();
    
    EXPECT_EQ(signal2[0], 8);
    EXPECT_EQ(signal2[1], 8);
    EXPECT_EQ(signal2[2], 8);
    EXPECT_EQ(signal2[3], 8);
    
    // Test case 3: Mixed values
    std::vector<uint64_t> coeffs3 = {2, 6, 8, 14};  // 2->0, 6->8, 8->8, 14->0
    f.setCoefficients(coeffs3);
    Polynomial signal3 = f.polySignal();
    
    EXPECT_EQ(signal3[0], 0);
    EXPECT_EQ(signal3[1], 8);
    EXPECT_EQ(signal3[2], 8);
    EXPECT_EQ(signal3[3], 0);
}

TEST_F(PolynomialTest, MultiplicationWithReduction) {
    // Create polynomials that will need reduction modulo x^4 + 1
    // f = x^3, g = x^2
    Polynomial f({0, 0, 0, 1}, q);
    Polynomial g({0, 0, 1, 0}, q);
    
    // Expected: x^5 = x * x^4 = -x mod (x^4 + 1)
    Polynomial h = f * g;
    
    EXPECT_EQ(h[0], 0);
    EXPECT_EQ(h[1], 16); // -1 mod 17
    EXPECT_EQ(h[2], 0);
    EXPECT_EQ(h[3], 0);
}

TEST_F(PolynomialTest, MultiplicationWithReductionExamples) {
    // Test in Z[x]/(x^4 + 1) with modulus 17
    // const size_t n = 2;  // degree will be 2n = 4
    const uint64_t q = 17;

    // Test case 1: x^3 * x^2 = x^5 = -x
    {
        Polynomial f({0, 0, 0, 1}, q);  // x^3
        Polynomial g({0, 0, 1, 0}, q);  // x^2
        Polynomial h = f * g;           // should be -x
        
        EXPECT_EQ(h[0], 0);
        EXPECT_EQ(h[1], 16);  // -1 mod 17
        EXPECT_EQ(h[2], 0);
        EXPECT_EQ(h[3], 0);
    }

    // Test case 2: x^3 * x^3 = x^6 = -x^2
    {
        Polynomial f({0, 0, 0, 1}, q);  // x^3
        Polynomial g({0, 0, 0, 1}, q);  // x^3
        Polynomial h = f * g;           // should be -x^2
        
        EXPECT_EQ(h[0], 0);
        EXPECT_EQ(h[1], 0);
        EXPECT_EQ(h[2], 16);  // -1 mod 17
        EXPECT_EQ(h[3], 0);
    }

    // Test case 3: (1 + x^3) * (1 + x^2) = 1 + x^2 + x^3 + x^5 = 1 + x^2 + x^3 - x
    {
        Polynomial f({1, 0, 0, 1}, q);  // 1 + x^3
        Polynomial g({1, 0, 1, 0}, q);  // 1 + x^2
        Polynomial h = f * g;
        
        EXPECT_EQ(h[0], 1);     // 1
        EXPECT_EQ(h[1], 16);    // -1 (from x^5 = -x)
        EXPECT_EQ(h[2], 1);     // x^2
        EXPECT_EQ(h[3], 1);     // x^3
    }
}
