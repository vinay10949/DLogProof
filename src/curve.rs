//! Secp256k1 elliptic curve constants and parameters.
//!
//! This module defines the secp256k1 curve parameters used for the discrete logarithm
//! zero-knowledge proofs. The curve equation is: y² = x³ + 7 (mod p)

use ibig::{ibig, IBig};
use lazy_static::lazy_static;

lazy_static! {
    /// The prime field modulus for secp256k1
    /// P = 2^256 - 2^32 - 977
    pub static ref P: IBig = ibig!(2).pow(256) - ibig!(2).pow(32) - ibig!(977);
    
    /// The order of the generator point (number of points in the group)
    /// N = 2^256 - 432420386565659656852420866394968145599
    pub static ref N: IBig = ibig!(2).pow(256)
        - IBig::from_str_radix("432420386565659656852420866394968145599", 10).unwrap();
    
    /// Beta constant for endomorphism optimization
    /// Used in the GLV (Gallant-Lambert-Vanstone) method for faster scalar multiplication
    pub static ref BETA: IBig = IBig::from_str_radix(
        "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
        16
    )
    .unwrap();
    
    /// Generator point x-coordinate
    pub static ref GX: IBig = IBig::from_str_radix(
        "55066263022277343669578718895168534326250603453777594175500187360389116729240",
        10,
    )
    .unwrap();
    
    /// Generator point y-coordinate
    pub static ref GY: IBig = IBig::from_str_radix(
        "32670510020758816978083085130507043184471273380659243275938904335757337482424",
        10,
    )
    .unwrap();
    
    // Constants for endomorphism optimization
    pub(crate) static ref A1: IBig = IBig::from_str_radix("3086d221a7d46bcde86c90e49284eb15", 16).unwrap();
    pub(crate) static ref B1: IBig = IBig::from_str_radix("-e4437ed6010e88286f547fa90abfe4c3", 16).unwrap();
    pub(crate) static ref A2: IBig = IBig::from_str_radix("114ca50f7a8e2f3f657c1108d9d44cfd8", 16).unwrap();
}

/// Compute a mod P (the field modulus)
#[inline]
pub fn rem(a: &IBig) -> IBig {
    let r = a % &*P;
    if r < IBig::from(0) {
        &*P + r
    } else {
        r
    }
}

/// Compute a mod N (the curve order)
#[inline]
pub fn rem_n(a: &IBig) -> IBig {
    let r = a % &*N;
    if r < IBig::from(0) {
        &*N + r
    } else {
        r
    }
}

/// Compute the modular inverse of a number modulo P
pub fn invert(number: &IBig) -> IBig {
    let mut a = rem(number);
    let mut b = P.clone();
    let mut x = ibig!(0);
    let mut y = ibig!(1);
    let mut u = ibig!(1);
    let mut v = ibig!(0);
    
    while a != IBig::from(0) {
        let q = &b / &a;
        let r = &b % &a;
        let m = &x - &u * &q;
        let n = &y - &v * &q;
        b = a.clone();
        a = r;
        x = u;
        y = v;
        u = m;
        v = n;
    }
    rem(&x)
}

/// Helper function for endomorphism optimization
#[inline]
pub(crate) fn div_nearest(a: &IBig, b: &IBig) -> IBig {
    (a + b / ibig!(2)) / b
}

/// Split scalar for endomorphism optimization (GLV method)
pub(crate) fn split_scalar_endo(k: &IBig) -> (bool, IBig, bool, IBig) {
    let a1: &IBig = &A1;
    let b1: &IBig = &B1;
    let a2: &IBig = &A2;
    let b2 = a1;
    let c1 = div_nearest(&(b2 * k), &N);
    let c2 = div_nearest(&(-b1 * k), &N);
    let mut k1 = rem_n(&(k - &c1 * a1 - &c2 * a2));
    let mut k2 = rem_n(&(-&c1 * b1 - &c2 * b2));
    let k1neg = k1 > ibig!(2).pow(128);
    let k2neg = k2 > ibig!(2).pow(128);
    if k1neg {
        k1 = &*N - &k1;
    }
    if k2neg {
        k2 = &*N - &k2;
    }
    (k1neg, k1, k2neg, k2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rem_positive() {
        let a = ibig!(100);
        let result = rem(&a);
        assert_eq!(result, ibig!(100));
    }

    #[test]
    fn test_rem_negative() {
        let a = ibig!(-100);
        let result = rem(&a);
        assert!(result >= ibig!(0));
        assert!(result < *P);
    }

    #[test]
    fn test_invert() {
        let a = ibig!(5);
        let inv = invert(&a);
        let product = rem(&(&a * &inv));
        assert_eq!(product, ibig!(1));
    }
}
