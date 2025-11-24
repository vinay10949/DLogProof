//! Fiat-Shamir transformation for non-interactive zero-knowledge proofs.
//!
//! This module implements the hash function used to convert the interactive Schnorr
//! protocol into a non-interactive zero-knowledge proof using the Fiat-Shamir heuristic.

use crate::jacobi_point::PointJacobi;
use ibig::IBig;
use sha256::digest;

/// Hash points and metadata to generate a challenge value.
///
/// This implements the Fiat-Shamir transformation by hashing the session ID,
/// participant ID, and elliptic curve points to produce a deterministic challenge.
///
/// # Arguments
///
/// * `sid` - Session identifier (prevents replay attacks across sessions)
/// * `pid` - Participant identifier
/// * `points` - Vector of points to include in the hash (typically: G, Y, T)
///
/// # Returns
///
/// A challenge value as a big integer, derived from SHA-256 hash
pub fn hash_points(sid: &str, pid: i32, points: Vec<PointJacobi>) -> IBig {
    let mut data = Vec::new();
    
    // Include session ID
    data.extend_from_slice(sid.as_bytes());
    
    // Include participant ID
    data.extend_from_slice(&pid.to_le_bytes());
    
    // Include all points
    for point in points {
        data.extend_from_slice(&point.to_bytes());
    }
    
    // Compute SHA-256 hash
    let hash_hex = digest(&data);
    
    // Convert hex string to IBig
    IBig::from_str_radix(&hash_hex, 16)
        .expect("SHA-256 hex output should always be valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jacobi_point::Point;

    #[test]
    fn test_hash_deterministic() {
        let g = Point::generator();
        let g_jacobi = PointJacobi::from_affine(g.clone());
        
        let hash1 = hash_points("session1", 1, vec![g_jacobi.clone()]);
        let hash2 = hash_points("session1", 1, vec![g_jacobi.clone()]);
        
        assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    #[test]
    fn test_hash_different_inputs() {
        let g = Point::generator();
        let g_jacobi = PointJacobi::from_affine(g);
        
        let hash1 = hash_points("session1", 1, vec![g_jacobi.clone()]);
        let hash2 = hash_points("session2", 1, vec![g_jacobi.clone()]);
        let hash3 = hash_points("session1", 2, vec![g_jacobi.clone()]);
        
        assert_ne!(hash1, hash2, "Different session IDs should produce different hashes");
        assert_ne!(hash1, hash3, "Different participant IDs should produce different hashes");
    }
}
