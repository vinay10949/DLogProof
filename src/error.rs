//! Error types for the DLogProof library.

use std::fmt;

/// Errors that can occur during proof generation and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// Invalid proof provided for verification
    InvalidProof,
    
    /// Invalid point (not on the curve or point at infinity when not expected)
    InvalidPoint,
    
    /// Invalid scalar value (e.g., zero or out of range)
    InvalidScalar,
    
    /// Serialization error
    SerializationError(String),
    
    /// Deserialization error
    DeserializationError(String),
    
    /// Invalid input parameter
    InvalidInput(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::InvalidProof => write!(f, "Invalid proof: verification failed"),
            ProofError::InvalidPoint => write!(f, "Invalid elliptic curve point"),
            ProofError::InvalidScalar => write!(f, "Invalid scalar value"),
            ProofError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            ProofError::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            ProofError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl std::error::Error for ProofError {}

/// Result type alias for DLogProof operations.
pub type Result<T> = std::result::Result<T, ProofError>;
