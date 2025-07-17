#include <gtest/gtest.h>
#include "rlwe.h"

class RLWETest : public ::testing::Test {
protected:
    // Using small parameters for testing
    const size_t n = 4;        // Ring dimension (degree will be 8)
    const uint64_t q = 3329;   // Modulus (should be prime in practice)
    
    void SetUp() override {
        rlwe = std::make_unique<RLWESignature>(n, q);
    }
    
    std::unique_ptr<RLWESignature> rlwe;
};

TEST_F(RLWETest, KeyGeneration) {
    ASSERT_NO_THROW(rlwe->generateKeys());
    
    // Get public key
    auto [a, b] = rlwe->getPublicKey();
    
    // Check dimensions
    EXPECT_EQ(a.degree(), 2 * n);
    EXPECT_EQ(b.degree(), 2 * n);
    
    // Check modulus
    EXPECT_EQ(a.getModulus(), q);
    EXPECT_EQ(b.getModulus(), q);
}

TEST_F(RLWETest, SignAndVerify) {
    // Generate keys
    rlwe->generateKeys();
    
    // Create a test message
    std::vector<uint8_t> message = {0x12, 0x34}; // 16 bits
    
    // Sign message
    auto signature = rlwe->sign(message);
    
    // Verify signature
    bool verified = rlwe->verify(message, signature);
    EXPECT_TRUE(verified);
}

TEST_F(RLWETest, VerifyFailsOnTamperedMessage) {
    // Generate keys
    rlwe->generateKeys();
    
    // Create a test message
    std::vector<uint8_t> message = {0x12, 0x34};
    
    // Sign message
    auto signature = rlwe->sign(message);
    
    // Tamper with message
    std::vector<uint8_t> tampered_message = {0x12, 0x35};
    
    // Verify should fail
    bool verified = rlwe->verify(tampered_message, signature);
    EXPECT_FALSE(verified);
}
