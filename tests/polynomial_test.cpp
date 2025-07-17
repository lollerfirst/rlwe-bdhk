TEST_F(PolynomialTest, MultiplicationWithReductionExamples) {
    // Test in Z[x]/(x^4 + 1) with modulus 17
    const size_t n = 2;  // degree will be 2n = 4
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
