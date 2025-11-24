# DLogProof

**Non-Interactive Zero-Knowledge Discrete Logarithm Proof using Schnorr Protocol with Fiat-Shamir Transformation**


## Overview

DLogProof is a Rust library implementing a non-interactive zero-knowledge proof system for proving knowledge of discrete logarithms on the secp256k1 elliptic curve. It uses the Schnorr protocol with the Fiat-Shamir transformation to convert an interactive proof into a non-interactive one.

### What is a Discrete Logarithm Proof?

A discrete logarithm proof allows a **prover** to convince a **verifier** that they know a secret value `x` such that `Y = x·G` (where `G` is a generator point on an elliptic curve), **without revealing `x` itself**.

This is useful in cryptographic applications like:
- Anonymous credentials
- Digital signatures
- Privacy-preserving authentication
- Blockchain protocols

## Features

- ✅ **Non-interactive proofs** using Fiat-Shamir transformation
- ✅ **Secp256k1 curve** support (same curve used in Bitcoin/Ethereum)
- ✅ **Optimized point operations** using Jacobian coordinates
- ✅ **GLV endomorphism** optimization for faster scalar multiplication


## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
dlogproof = "0.1.0"
```



### Running the Example

```bash
cargo run --bin dlogproof-example
```

## How It Works

### Schnorr Protocol (Interactive)

1. **Prover**: Choose random `r`, compute `T = r·G`, send `T`
2. **Verifier**: Send random challenge `c`
3. **Prover**: Compute `s = r + c·x (mod n)`, send `s`
4. **Verifier**: Check if `s·G = T + c·Y`

### Fiat-Shamir Transformation (Non-Interactive)

The interactive protocol is made non-interactive by replacing the verifier's random challenge with a hash:

- **Challenge**: `c = H(session_id, participant_id, G, Y, T)`
- **Proof**: `(T, s)`
- **Verification**: Check if `s·G = T + c·Y` where `c = H(session_id, participant_id, G, Y, T)`

## Architecture

The library is organized into the following modules:

- **`curve`**: Secp256k1 curve constants and helper functions
- **`jacobi_point`**: Elliptic curve point arithmetic (affine and Jacobian coordinates)
- **`hash`**: Fiat-Shamir transformation (SHA-256 based)
- **`proof`**: Prover and Verifier implementations
- **`error`**: Error types and Result aliases


## Testing

Run all tests:

```bash
cargo test
```