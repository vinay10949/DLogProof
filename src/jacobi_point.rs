//! Elliptic curve point operations on secp256k1.
//!
//! This module implements point arithmetic in both affine and Jacobian coordinates
//! for the secp256k1 elliptic curve. Jacobian coordinates are used for efficient
//! point operations, avoiding expensive modular inversions during intermediate calculations.


use crate::curve::{self, rem};
use ibig::{ibig, IBig};
use num_traits::sign::Signed;
use std::ops::ShrAssign;

/// A point on the secp256k1 curve in Jacobian coordinates (X:Y:Z).
///
/// Jacobian coordinates represent a point (x, y) as (X, Y, Z) where:
/// - x = X / Z²
/// - y = Y / Z³
///
/// The point at infinity is represented as (0, 1, 0).
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PointJacobi {
    pub x: IBig,
    pub y: IBig,
    pub z: IBig,
}

impl PointJacobi {
    /// Create a new point in Jacobian coordinates.
    pub fn new(x: IBig, y: IBig, z: IBig) -> Self {
        Self { x, y, z }
    }

    /// Return the point at infinity (identity element).
    pub fn zero() -> Self {
        Self {
            x: ibig!(0),
            y: ibig!(1),
            z: ibig!(0),
        }
    }

    /// Check if this is the point at infinity.
    pub fn is_zero(&self) -> bool {
        self.z == ibig!(0)
    }

    /// Convert an affine point to Jacobian coordinates.
    pub fn from_affine(p: Point) -> Self {
        Self::new(p.x, p.y, ibig!(1))
    }

    /// Convert this Jacobian point to affine coordinates.
    ///
    /// # Panics
    ///
    /// Panics if this is the point at infinity (Z = 0).
    pub fn to_affine(&self) -> Point {
        let inv_z = curve::invert(&self.z);
        let inv_z_pow = inv_z.pow(2);
        let x = rem(&(&self.x * &inv_z_pow));
        let y = rem(&(&self.y * &inv_z * &inv_z_pow));
        Point::new(x, y)
    }

    /// Negate this point (flip the y-coordinate).
    pub fn negate(self) -> Self {
        Self::new(self.x, rem(&-self.y), self.z)
    }

    /// Double this point: compute 2P.
    pub fn double(&self) -> Self {
        let a = rem(&self.x.pow(2));
        let b = rem(&self.y.pow(2));
        let c = rem(&b.pow(2));
        let d = rem(&(ibig!(2) * rem(&(rem(&(&self.x + &b).pow(2)) - &a - &c))));
        let e = rem(&(ibig!(3) * &a));
        let f = rem(&e.pow(2));
        let x3 = rem(&(&f - &d * ibig!(2)));
        let y3 = rem(&(&e * (&d - &x3) - &c * ibig!(8)));
        let z3 = rem(&(&self.y * &self.z * ibig!(2)));
        Self::new(x3, y3, z3)
    }

    /// Add two points: compute P + Q.
    pub fn add(&self, other: &Self) -> Self {
        // Handle point at infinity cases
        if other.is_zero() {
            return self.clone();
        }
        if self.is_zero() {
            return other.clone();
        }

        let z1z1 = self.z.pow(2);
        let z2z2 = other.z.pow(2);
        let u1 = rem(&(&self.x * &z2z2));
        let u2 = rem(&(&other.x * &z1z1));
        let s1 = rem(&(&self.y * &other.z * &z2z2));
        let s2 = rem(&(rem(&(&other.y * &self.z)) * &z1z1));
        let h = rem(&(&u2 - &u1));
        let r = rem(&(&s2 - &s1));

        if h == ibig!(0) {
            if r == ibig!(0) {
                // Points are equal, use doubling
                self.double()
            } else {
                // Points are negatives of each other
                Self::zero()
            }
        } else {
            let hh = rem(&h.pow(2));
            let hhh = rem(&(&h * &hh));
            let v = rem(&(&u1 * &hh));
            let x3 = rem(&(&r.pow(2) - &hhh - &v * ibig!(2)));
            let y3 = rem(&(&r * (&v - &x3) - &s1 * &hhh));
            let z3 = rem(&(&self.z * &other.z * &h));
            Self::new(x3, y3, z3)
        }
    }

    /// Scalar multiplication: compute k * P.
    ///
    /// This uses the GLV (Gallant-Lambert-Vanstone) endomorphism optimization
    /// for faster scalar multiplication on secp256k1.
    pub fn mul(&self, scalar: &IBig) -> Self {
        let (k1neg, mut k1, k2neg, mut k2) = curve::split_scalar_endo(scalar);
        let mut k1p = Self::zero();
        let mut k2p = Self::zero();
        let mut d = self.clone();

        while k1.is_positive() || k2.is_positive() {
            if (&k1 & 1_u8) != 0 {
                k1p = k1p.add(&d);
            }
            if (&k2 & 1_u8) != 0 {
                k2p = k2p.add(&d);
            }
            d = d.double();
            k1.shr_assign(1);
            k2.shr_assign(1);
        }

        if k1neg {
            k1p = k1p.negate();
        }
        if k2neg {
            k2p = k2p.negate();
        }

        let beta: &IBig = &curve::BETA;
        k2p = Self::new(rem(&(&k2p.x * beta)), k2p.y.clone(), k2p.z.clone());
        k1p.add(&k2p)
    }

    /// Serialize this point to bytes.
    ///
    /// Returns the concatenation of x, y, z coordinates as byte arrays.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let x_bytes = self.x.to_string().into_bytes();
        let y_bytes = self.y.to_string().into_bytes();
        let z_bytes = self.z.to_string().into_bytes();
        bytes.extend_from_slice(&(x_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&x_bytes);
        bytes.extend_from_slice(&(y_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&y_bytes);
        bytes.extend_from_slice(&(z_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&z_bytes);
        bytes
    }
}

/// A point on the secp256k1 curve in affine coordinates (x, y).
///
/// The point at infinity is represented as (0, 0).
#[derive(Debug, Clone)]
pub struct Point {
    pub x: IBig,
    pub y: IBig,
}

impl Point {
    /// Create a new point in affine coordinates.
    pub fn new(x: IBig, y: IBig) -> Self {
        Self { x, y }
    }

    /// Return the point at infinity (identity element).
    pub fn zero() -> Self {
        Self::new(ibig!(0), ibig!(0))
    }

    /// Check if this is the point at infinity.
    pub fn is_zero(&self) -> bool {
        self.x == ibig!(0) && self.y == ibig!(0)
    }

    /// Return the secp256k1 generator point G.
    pub fn generator() -> Self {
        Self::new(curve::GX.clone(), curve::GY.clone())
    }

    /// Scalar multiplication: compute k * P.
    ///
    /// This converts to Jacobian coordinates, performs the multiplication,
    /// and converts back to affine coordinates.
    pub fn mul(&self, scalar: &IBig) -> Self {
        let pj = PointJacobi::from_affine(self.clone());
        pj.mul(scalar).to_affine()
    }

    /// Serialize this point to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let x_bytes = self.x.to_string().into_bytes();
        let y_bytes = self.y.to_string().into_bytes();
        bytes.extend_from_slice(&(x_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&x_bytes);
        bytes.extend_from_slice(&(y_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&y_bytes);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point_at_infinity() {
        let zero = PointJacobi::zero();
        assert!(zero.is_zero());
        
        let g = PointJacobi::from_affine(Point::generator());
        assert!(!g.is_zero());
    }

    #[test]
    fn test_point_addition() {
        let g = PointJacobi::from_affine(Point::generator());
        let zero = PointJacobi::zero();
        
        // G + 0 = G
        let result = g.add(&zero);
        assert_eq!(result, g);
        
        // 0 + G = G
        let result = zero.add(&g);
        assert_eq!(result, g);
    }

    #[test]
    fn test_point_doubling() {
        let g = Point::generator();
        let g_jacobi = PointJacobi::from_affine(g.clone());
        
        // 2G using doubling
        let double = g_jacobi.double();
        
        // 2G using multiplication
        let mul2 = g.mul(&ibig!(2));
        
        assert_eq!(double.to_affine().x, mul2.x);
        assert_eq!(double.to_affine().y, mul2.y);
    }

    #[test]
    fn test_scalar_multiplication() {
        let g = Point::generator();
        let scalar = ibig!(12345);
        
        let result = g.mul(&scalar);
        assert!(!result.is_zero());
    }

    #[test]
    fn test_affine_jacobian_conversion() {
        let g = Point::generator();
        let g_jacobi = PointJacobi::from_affine(g.clone());
        let g_back = g_jacobi.to_affine();
        
        assert_eq!(g.x, g_back.x);
        assert_eq!(g.y, g_back.y);
    }
}
