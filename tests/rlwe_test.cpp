#include <gtest/gtest.h>
#include "rlwe.h"
#include "logging.h"
#include <iostream>

class RLWETest : public ::testing::Test {
protected:
    // Using parameters large enough for test messages
    const size_t n = 8;        // Ring dimension (degree will be 16)
    const uint64_t q = 7681;   // Modulus (should be prime in practice)
    
    void SetUp() override {
        rlwe = std::make_unique<RLWESignature>(n, q);
        Logger::enable_logging = false;
    }
    
    std::unique_ptr<RLWESignature> rlwe;
};

TEST_F(RLWETest, KeyGeneration) {
    ASSERT_NO_THROW(rlwe->generateKeys());
    auto [a, b] = rlwe->getPublicKey();
    EXPECT_EQ(a.degree(), 2 * n);
    EXPECT_EQ(b.degree(), 2 * n);
    EXPECT_EQ(a.getModulus(), q);
    EXPECT_EQ(b.getModulus(), q);
}

TEST_F(RLWETest, SignAndVerify) {
    rlwe->generateKeys();
    std::vector<uint8_t> message = {0x12, 0x34};
    auto signature = rlwe->sign(message);
    bool verified = rlwe->verify(message, signature);
    EXPECT_TRUE(verified);
}

TEST_F(RLWETest, VerifyFailsOnTamperedMessage) {
    Logger::setOutputStream(std::cout);
    Logger::enable_logging = true;
    std::cout << "\nRunning VerifyFailsOnTamperedMessage test...\n";

    rlwe->generateKeys();
    std::vector<uint8_t> message = {0x12, 0x34};
    
    std::cout << "\n=== Signing original message ===\n";
    auto signature = rlwe->sign(message);
    
    std::cout << "\n=== Verifying tampered message ===\n";
    std::vector<uint8_t> tampered_message = {0x12, 0x35};
    bool verified = rlwe->verify(tampered_message, signature);
    
    std::cout << "\nVerification result: " << (verified ? "true" : "false") << "\n";
    Logger::enable_logging = false;
    
    EXPECT_FALSE(verified);
}
