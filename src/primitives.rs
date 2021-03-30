use std::convert::TryInto;

use bellman::{bn256, CurveAffine, PrimeField, PrimeFieldRepr};

pub fn serialize_fe_for_ethereum(field_element: &bn256::Fr) -> [u8; 32] {
    let mut be_bytes = [0u8; 32];
    field_element
        .into_repr()
        .write_be(&mut be_bytes[..])
        .expect("get new root BE bytes");

    be_bytes
}

pub fn serialize_g1_for_ethereum(point: &bn256::G1Affine) -> ([u8; 32], [u8; 32]) {
    if point.is_zero() {
        return ([0u8; 32], [0u8; 32]);
    }

    let uncompressed = point.into_uncompressed();

    // bellman serializes points as big endian and in the form x, y
    // ethereum expects the same order in memory
    (
        uncompressed.as_ref()[0..32].try_into().unwrap(),
        uncompressed.as_ref()[32..64].try_into().unwrap(),
    )
}
