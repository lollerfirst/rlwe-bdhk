# RLWE Blind DH Exchange

This project implements a Ring Learning With Errors (RLWE) based blind exchange protocol, designed as an alternative to the current BDHKE (Blind Diffie-Hellman Key Exchange) used in Cashu. This implementation replaces elliptic curve primitives with lattice-based cryptography primitives that are believed to be quantum-resistant.

## Overview

The blind exchange protocol works in the polynomial ring $R = Z[x]/(x^n + 1)$ and replaces key Cashu operations with RLWE equivalents:

### Key Transformations

- **Point-Scalar Multiplication → Noisy Polynomial Multiplication**
  - Instead of ECC point-scalar multiplication, we use RLWE's fundamental operation: `a * s + e`
  - Where:
    - `a` and `s` are polynomials
    - `e` is a small "error" polynomial sampled from a Gaussian distribution
    
- **Point Addition → Polynomial Addition**
  - ECC point addition is replaced by simple polynomial addition in the ring
  - Operations are performed modulo both the ring polynomial $(x^n + 1)$ and a prime modulus q

### Key Function Replacements

- **hashToCurve → hashToPoly**
  - Cashu's `hashToCurve` function is replaced with `hashToPoly`
  - `hashToPoly` takes a secret message and maps it to a polynomial using SHA256
  - The resulting polynomial maintains the security properties needed for the blind exchange

### Security Basis

The security of this implementation relies on the Ring Learning With Errors problem, which is considered to be:
- Quantum-resistant (unlike ECC-based systems)
- Shown to be as hard as solving worst-case lattice problems

## Warning

This is an experimental implementation meant for research and learning purposes. It should not be used in production environments without thorough security review and analysis.
