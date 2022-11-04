mod JacobiPoint;
use crate::JacobiPoint::{Point, PointJacobi};
use ibig::IBig;
use rand::Rng;
use sha256::digest;
use std::collections::HashMap;

fn generate_random_number() -> i32 {
    let mut rng = rand::thread_rng();
    rng.gen_range(1..50)
}

struct DLogProof {
    t: PointJacobi,
    s: IBig,
}

impl DLogProof {
    /*
       Non-interactive Schnorr ZK DLOG Proof scheme with a Fiat-Shamir transformation
       ";

    */

    /// `hash_points` takes a string, an integer, and a vector of points, and returns a big integer
    ///
    /// Arguments:
    ///
    /// * `sid`: the id of the signature
    /// * `pid`: the id of the point
    /// * `points`: The points that are being hashed.
    ///
    /// Returns:
    ///
    /// A hash of the points.
    fn hash_points(sid: &str, pid: i32, points: Vec<PointJacobi>) -> IBig {
        let mut point_feild = vec![];
        point_feild.extend(sid.as_bytes());
        point_feild.extend(IBig::from(pid).to_string().as_bytes());
        for point in points {
            point_feild.extend(point.as_bytes());
        }
        let digest = digest(&point_feild[..]);
        IBig::from_str_radix(&digest, 32).unwrap()
    }

    /// > The prover generates a random number `r`, computes `t = r*G` and `c = H(sid, pid, G, y, t)`,
    /// and then computes `s = r + c*x` and returns the proof `(t, s)`
    ///
    /// Arguments:
    ///
    /// * `sid`: the signature id
    /// * `pid`: the participant id
    /// * `x`: the secret number
    /// * `y`: the point that we want to prove that we know the discrete logarithm of
    /// * `base_point`: The base point of the group.
    ///
    /// Returns:
    ///
    /// A DLogProof struct containing the t and s values.
    fn prove(sid: &str, pid: i32, x: i32, y: PointJacobi, base_point: PointJacobi) -> DLogProof {
        "y = x*G";
        let r = generate_random_number();
        let t = base_point.mul_unsafe(&IBig::from(r));
        let c = DLogProof::hash_points(sid, pid, vec![base_point, y, t.clone()]);
        let curve_order: IBig = IBig::from_str_with_radix_prefix(
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
        )
        .unwrap();
        let s = (r + (c * x)) % curve_order;
        return DLogProof { t, s };
    }

    /// > The function verifies that the point `t` is the sum of the base point multiplied by `s` and
    /// the point `y` multiplied by the hash of the inputs
    ///
    /// Arguments:
    ///
    /// * `sid`: the session id
    /// * `pid`: the id of the prover
    /// * `y`: the public key
    /// * `base_point`: the base point of the group
    ///
    /// Returns:
    ///
    /// a boolean value.
    fn verify(&self, sid: &str, pid: i32, y: PointJacobi, base_point: PointJacobi) -> bool {
        let c = DLogProof::hash_points(
            sid,
            pid,
            vec![base_point.clone(), y.clone(), self.t.clone()],
        );
        let lhs = base_point.mul_unsafe(&self.s);
        let rhs = self.t.add(&y.mul_unsafe(&c));
        lhs == rhs
    }
}

fn main() {
    let sid = "sid";
    let pid = 1;
    let x = generate_random_number();
    println!("{:?} ", x);
    let private_key = IBig::from_str_radix(
        "20775598474904240222758871485654738649026525153462921990999819694398496339603",
        10,
    )
    .unwrap();

    let base_point = Point::generator();
    let mut point = base_point.clone();
    for _i in 1..25 {
        point = point.mul(&private_key);
    }
    println!("{:x},{:x}", point.x, point.y);
    let start_proof = std::time::Instant::now();
    let dlog_proof = DLogProof::prove(
        sid,
        pid,
        x as i32,
        PointJacobi::from_affine(point.clone()),
        PointJacobi::from_affine(base_point.clone()),
    );
    println!(
        "Proof computation time {:?} ",
        start_proof.elapsed().as_millis()
    );
    println!("Proof {:?} {:?} ", dlog_proof.t.x, dlog_proof.t.y);
    println!("Proof {:?} ", dlog_proof.s);
    let result = dlog_proof.verify(
        sid,
        pid,
        PointJacobi::from_affine(point),
        PointJacobi::from_affine(base_point),
    );
    println!(
        "Verify computation time: {:?} ",
        start_proof.elapsed().as_millis()
    );
    if result {
        println!("{:?} ", "DLOG proof is correct");
    } else {
        println!("{:?} ", "DLOG proof is not correct");
    }
}
