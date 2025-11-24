//! Non-Interactive Zero-Knowledge Discrete Logarithm Proof (Schnorr Protocol).
//!
//! This module implements a non-interactive zero-knowledge proof system for proving
//! knowledge of a discrete logarithm using the Schnorr protocol with Fiat-Shamir
//! transformation.
//!
//! # Protocol Overview
//!
//! **Prover wants to prove:** "I know x such that Y = x·G" (without revealing x)
//!
//! **Interactive Schnorr Protocol:**
//! 1. Prover: Choose random r, compute T = r·G, send T
//! 2. Verifier: Send random challenge c
//! 3. Prover: Compute s = r + c·x (mod n), send s
//! 4. Verifier: Check if s·G = T + c·Y
//!
//! **Non-Interactive (Fiat-Shamir):**
//! - Replace step 2 with c = H(sid, pid, G, Y, T)
//! - Proof is (T, s), verification checks s·G = T + c·Y where c = H(sid, pid, G, Y, T)

use crate::curve::rem_n;
use crate::error::{ProofError, Result};
use crate::hash::hash_points;
use crate::jacobi_point::PointJacobi;
use ibig::IBig;
use rand::Rng;

/// A discrete logarithm zero-knowledge proof.
///
/// This proof demonstrates knowledge of a secret value x such that Y = x·G,
/// without revealing x.
#[derive(Debug, Clone)]
pub struct DLogProof {
    /// The commitment point T = r·G (where r is a random nonce)
    pub t: PointJacobi,
    
    /// The response s = r + c·x (mod n), where c is the challenge
    pub s: IBig,
}

impl DLogProof {
    /// Create a new proof given the commitment and response.
    pub fn new(t: PointJacobi, s: IBig) -> Self {
        Self { t, s }
    }

    /// Serialize the proof to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.t.to_bytes());
        let s_bytes = self.s.to_string().into_bytes();
        bytes.extend_from_slice(&(s_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&s_bytes);
        bytes
    }
}

/// Prover for discrete logarithm zero-knowledge proofs.
pub struct Prover;

impl Prover {
    /// Generate a zero-knowledge proof that you know the discrete logarithm x
    /// such that Y = x·G.
    ///
    /// # Arguments
    ///
    /// * `sid` - Session identifier (prevents replay attacks)
    /// * `pid` - Participant identifier
    /// * `secret` - The secret value x (discrete logarithm)
    /// * `public_key` - The public key Y = x·G
    /// * `base_point` - The generator point G
    ///
    /// # Returns
    ///
    /// A `DLogProof` containing the commitment T and response s.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let g = Point::generator();
    /// let secret = IBig::from(42);
    /// let public_key = g.mul(&secret);
    ///
    /// let proof = Prover::prove(
    ///     "session1",
    ///     1,
    ///     &secret,
    ///     &PointJacobi::from_affine(public_key),
    ///     &PointJacobi::from_affine(g),
    /// );
    /// ```
    pub fn prove(
        sid: &str,
        pid: i32,
        secret: &IBig,
        public_key: &PointJacobi,
        base_point: &PointJacobi,
    ) -> DLogProof {
        // Step 1: Generate random nonce r
        let r = Self::generate_random_nonce();

        // Step 2: Compute commitment T = r·G
        let t = base_point.mul(&r);

        // Step 3: Compute challenge c = H(sid, pid, G, Y, T) using Fiat-Shamir
        let c = hash_points(
            sid,
            pid,
            vec![base_point.clone(), public_key.clone(), t.clone()],
        );

        // Step 4: Compute response s = r + c·x (mod n)
        let s = rem_n(&(r + &c * secret));

        DLogProof::new(t, s)
    }

    /// Generate a random nonce for the proof.
    ///
    /// In production, this should use a cryptographically secure random number
    /// generator and ensure the nonce is in the valid range [1, n-1].
    fn generate_random_nonce() -> IBig {
        let mut rng = rand::thread_rng();
        // Generate a random number in a reasonable range
        // For production, this should be in [1, curve_order - 1]
        IBig::from(rng.gen_range(1..1_000_000_000))
    }
}

/// Verifier for discrete logarithm zero-knowledge proofs.
pub struct Verifier;

impl Verifier {
    /// Verify a zero-knowledge proof that the prover knows x such that Y = x·G.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify
    /// * `sid` - Session identifier (must match the one used in proof generation)
    /// * `pid` - Participant identifier (must match the one used in proof generation)
    /// * `public_key` - The claimed public key Y
    /// * `base_point` - The generator point G
    ///
    /// # Returns
    ///
    /// `Ok(())` if the proof is valid, `Err(ProofError::InvalidProof)` otherwise.
    ///
    /// # Verification Equation
    ///
    /// The verifier checks: s·G = T + c·Y
    ///
    /// Where c = H(sid, pid, G, Y, T) is recomputed by the verifier.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let result = Verifier::verify(
    ///     &proof,
    ///     "session1",
    ///     1,
    ///     &public_key_jacobi,
    ///     &g_jacobi,
    /// );
    /// assert!(result.is_ok());
    /// ```
    pub fn verify(
        proof: &DLogProof,
        sid: &str,
        pid: i32,
        public_key: &PointJacobi,
        base_point: &PointJacobi,
    ) -> Result<()> {
        // Step 1: Recompute challenge c = H(sid, pid, G, Y, T)
        let c = hash_points(
            sid,
            pid,
            vec![base_point.clone(), public_key.clone(), proof.t.clone()],
        );

        // Step 2: Compute left-hand side: s·G
        let lhs = base_point.mul(&proof.s);

        // Step 3: Compute right-hand side: T + c·Y
        let rhs = proof.t.add(&public_key.mul(&c));

        // Step 4: Check if s·G = T + c·Y
        // Note: We must compare affine coordinates because Jacobian coordinates
        // can represent the same point with different Z values
        let lhs_affine = lhs.to_affine();
        let rhs_affine = rhs.to_affine();
        
        if lhs_affine.x == rhs_affine.x && lhs_affine.y == rhs_affine.y {
            Ok(())
        } else {
            Err(ProofError::InvalidProof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jacobi_point::Point;

    #[test]
    fn test_valid_proof() {
        let g = Point::generator();
        let g_jacobi = PointJacobi::from_affine(g.clone());
        
        let secret = IBig::from(42);
        let public_key = g.mul(&secret);
        let public_key_jacobi = PointJacobi::from_affine(public_key);

        let proof = Prover::prove(
            "test_session",
            1,
            &secret,
            &public_key_jacobi,
            &g_jacobi,
        );

        let result = Verifier::verify(
            &proof,
            "test_session",
            1,
            &public_key_jacobi,
            &g_jacobi,
        );

        assert!(result.is_ok(), "Valid proof should verify successfully");
    }

    #[test]
    fn test_invalid_proof_wrong_secret() {
        let g = Point::generator();
        let g_jacobi = PointJacobi::from_affine(g.clone());
        
        let secret = IBig::from(42);
        let wrong_secret = IBig::from(99);
        
        let public_key = g.mul(&secret);
        let public_key_jacobi = PointJacobi::from_affine(public_key);

        // Create proof with wrong secret
        let proof = Prover::prove(
            "test_session",
            1,
            &wrong_secret,
            &public_key_jacobi,
            &g_jacobi,
        );

        let result = Verifier::verify(
            &proof,
            "test_session",
            1,
            &public_key_jacobi,
            &g_jacobi,
        );

        assert!(result.is_err(), "Invalid proof should fail verification");
    }

    #[test]
    fn test_different_session_id() {
        let g = Point::generator();
        let g_jacobi = PointJacobi::from_affine(g.clone());
        
        let secret = IBig::from(42);
        let public_key = g.mul(&secret);
        let public_key_jacobi = PointJacobi::from_affine(public_key);

        let proof = Prover::prove(
            "session1",
            1,
            &secret,
            &public_key_jacobi,
            &g_jacobi,
        );

        // Try to verify with different session ID
        let result = Verifier::verify(
            &proof,
            "session2",
            1,
            &public_key_jacobi,
            &g_jacobi,
        );

        assert!(result.is_err(), "Proof should fail with different session ID");
    }

    #[test]
    fn test_proof_determinism_with_different_nonces() {
        let g = Point::generator();
        let g_jacobi = PointJacobi::from_affine(g.clone());
        
        let secret = IBig::from(42);
        let public_key = g.mul(&secret);
        let public_key_jacobi = PointJacobi::from_affine(public_key);

        // Generate two proofs with the same inputs
        let proof1 = Prover::prove(
            "test_session",
            1,
            &secret,
            &public_key_jacobi,
            &g_jacobi,
        );

        let proof2 = Prover::prove(
            "test_session",
            1,
            &secret,
            &public_key_jacobi,
            &g_jacobi,
        );

        // Proofs should be different (due to random nonce)
        assert_ne!(proof1.s, proof2.s, "Proofs should differ due to random nonce");

        // But both should verify
        assert!(Verifier::verify(&proof1, "test_session", 1, &public_key_jacobi, &g_jacobi).is_ok());
        assert!(Verifier::verify(&proof2, "test_session", 1, &public_key_jacobi, &g_jacobi).is_ok());
    }
}
