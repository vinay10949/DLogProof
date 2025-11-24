//! DLogProof: Non-Interactive Zero-Knowledge Discrete Logarithm Proofs
//!
//! This library implements a non-interactive zero-knowledge proof system for proving
//! knowledge of discrete logarithms on the secp256k1 elliptic curve using the Schnorr
//! protocol with Fiat-Shamir transformation.
//!
//! # Overview
//!
//! A discrete logarithm proof allows a prover to convince a verifier that they know
//! a secret value `x` such that `Y = x·G` (where G is a generator point), without
//! revealing `x` itself.
pub mod curve;
pub mod error;
pub mod hash;
pub mod jacobi_point;
pub mod proof;

// Re-export commonly used types
pub use error::{ProofError, Result};
pub use jacobi_point::{Point, PointJacobi};
pub use proof::{DLogProof, Prover, Verifier};
