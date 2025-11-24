//! Example demonstrating the DLogProof library.
//!
//! This example shows how to:
//! 1. Generate a secret and corresponding public key
//! 2. Create a zero-knowledge proof of knowledge of the discrete logarithm
//! 3. Verify the proof
//! 4. Demonstrate that invalid proofs fail verification

use dlogproof::{Point, PointJacobi, Prover, Verifier};
use ibig::IBig;
use std::time::Instant;

fn main() {
    println!("=== DLogProof: Non-Interactive Zero-Knowledge Discrete Logarithm Proof ===\n");

    // Session and participant identifiers
    let session_id = "example_session";
    let participant_id = 1;

    // Generate the base point (generator)
    let g = Point::generator();
    let g_jacobi = PointJacobi::from_affine(g.clone());

    println!("1. Generating secret and public key...");
    
    // Generate a secret value (this is what we want to prove knowledge of)
    let secret = IBig::from(123456789);
    
    // Compute the public key: Y = secret * G
    let public_key = g.mul(&secret);
    let public_key_jacobi = PointJacobi::from_affine(public_key);
    
    println!("   Secret: {} (this would normally be kept private!)", secret);
    println!("   Public key computed: Y = secret * G\n");

    // ===== VALID PROOF EXAMPLE =====
    println!("2. Creating zero-knowledge proof...");
    let start_proof = Instant::now();
    
    let proof = Prover::prove(
        session_id,
        participant_id,
        &secret,
        &public_key_jacobi,
        &g_jacobi,
    );
    
    let proof_time = start_proof.elapsed();
    println!("   Proof created in {:?}", proof_time);
    println!("   Proof response (s): {}\n", proof.s);

    println!("3. Verifying the proof...");
    let start_verify = Instant::now();
    
    let result = Verifier::verify(
        &proof,
        session_id,
        participant_id,
        &public_key_jacobi,
        &g_jacobi,
    );
    
    let verify_time = start_verify.elapsed();
    println!("   Verification completed in {:?}", verify_time);
    
    match result {
        Ok(()) => println!("   ✓ Proof is VALID! The prover knows the discrete logarithm.\n"),
        Err(e) => println!("   ✗ Proof is INVALID: {}\n", e),
    }

    // ===== INVALID PROOF EXAMPLE =====
    println!("4. Testing with an invalid proof (wrong secret)...");
    
    let wrong_secret = IBig::from(999999999);
    let invalid_proof = Prover::prove(
        session_id,
        participant_id,
        &wrong_secret,  // Using wrong secret!
        &public_key_jacobi,
        &g_jacobi,
    );
    
    let invalid_result = Verifier::verify(
        &invalid_proof,
        session_id,
        participant_id,
        &public_key_jacobi,
        &g_jacobi,
    );
    
    match invalid_result {
        Ok(()) => println!("   ✗ Unexpected: Invalid proof was accepted!"),
        Err(e) => println!("   ✓ As expected, invalid proof was rejected: {}\n", e),
    }

    // ===== PERFORMANCE SUMMARY =====
    println!("=== Performance Summary ===");
    println!("Proof generation: {:?}", proof_time);
    println!("Proof verification: {:?}", verify_time);

}

