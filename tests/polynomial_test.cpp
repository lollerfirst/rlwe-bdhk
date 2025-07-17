#include <gtest/gtest.h>
#include "polynomial.h"

class PolynomialTest : public ::testing::Test {
protected:
    // Will be used as Z[x]/(x^4 + 1) mod 17
    const size_t n = 2;  // degree will be 2n = 4
    const uint64_t q = 17;
};

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
