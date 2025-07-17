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
    Logger::setOutputStream(std::cout);
    Logger::enable_logging = true;
    rlwe->generateKeys();
    std::vector<uint8_t> message = {0x12, 0x34};
    auto signature = rlwe->sign(message);
    bool verified = rlwe->verify(message, signature);
    EXPECT_TRUE(verified);
}

TEST_F(RLWETest, VerifyFailsOnTamperedMessage) {
    Logger::setOutputStream(std::cout);
    Logger::enable_logging = false;
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

TEST_F(RLWETest, VerifyFailsOnForgedSignature) {
    Logger::setOutputStream(std::cout);
    Logger::enable_logging = false;
    std::cout << "\nRunning VerifyFailsOnForgedSignature test...\n";

    rlwe->generateKeys();
    std::vector<uint8_t> message = {0x12, 0x34};

    // Create forged signature components
    Polynomial z1(2 * n, q);  // Random polynomial
    Polynomial z2(2 * n, q);  // Random polynomial
    
    // Set some coefficients to attempt forgery
    std::vector<uint64_t> forged_coeffs1(2 * n, 1);  // All ones
    std::vector<uint64_t> forged_coeffs2(2 * n, 2);  // All twos
    
    z1.setCoefficients(forged_coeffs1);
    z2.setCoefficients(forged_coeffs2);
    
    std::cout << "\n=== Attempting verification with forged signature ===\n";
    auto forged_signature = std::make_pair(z1, z2);
    bool verified = rlwe->verify(message, forged_signature);
    
    std::cout << "\nVerification result: " << (verified ? "true" : "false") << "\n";
    Logger::enable_logging = false;
    
    EXPECT_FALSE(verified);
}

TEST_F(RLWETest, VerifyFailsOnZeroSignature) {
    Logger::setOutputStream(std::cout);
    Logger::enable_logging = false;
    std::cout << "\nRunning VerifyFailsOnZeroSignature test...\n";

    rlwe->generateKeys();
    std::vector<uint8_t> message = {0x12, 0x34};

    // Create zero polynomials
    Polynomial zero1(2 * n, q);  // Zero polynomial
    Polynomial zero2(2 * n, q);  // Zero polynomial
    
    // Keep coefficients as zero
    std::vector<uint64_t> zero_coeffs(2 * n, 0);
    zero1.setCoefficients(zero_coeffs);
    zero2.setCoefficients(zero_coeffs);
    
    std::cout << "\n=== Attempting verification with zero signature ===\n";
    auto zero_signature = std::make_pair(zero1, zero2);
    bool verified = rlwe->verify(message, zero_signature);
    
    std::cout << "\nVerification result: " << (verified ? "true" : "false") << "\n";
    Logger::enable_logging = false;
    
    EXPECT_FALSE(verified);
}
