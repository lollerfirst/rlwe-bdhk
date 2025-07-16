# RLWE Signature Experiment

This project implements a Ring Learning With Errors (RLWE) signature scheme. The implementation is experimental and meant for learning purposes.

## Overview

The signature scheme is based on the RLWE problem and works in the polynomial ring R = Z[x]/(x^(2n) + 1). The scheme consists of:

### Key Generation
- Generate uniform random polynomial `a`
- Generate two "small" polynomials `s` and `e` from Gaussian distribution
- Public key: (a, b = a*s + e)
- Private key: s

### Signature Generation
The signature generation involves:
- Random 'small' elements r, e1, e2 from Gaussian distribution
- u = a·r + e1 mod q
- v = b·r + e2 + ⌊q/2⌋·z mod q

### Verification/Decryption
v − u·s = (r·e − s·e1 + e2) + ⌊q/2⌋·z mod q

The coefficients of (r·e − s·e1 + e2) have magnitudes less than q/4, allowing recovery of z by rounding coefficients to either 0 or ⌊q/2⌋.

## Warning
This is an experimental implementation and should not be used in production environments.
