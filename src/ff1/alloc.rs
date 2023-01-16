//! FF1 NumeralString implementations that require a global allocator.

use core::iter;

use alloc::{vec, vec::Vec};

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{
    identities::{One, Zero},
    ToPrimitive,
};

use super::{NumeralString, Operations};

fn pow(x: u32, e: usize) -> BigUint {
    let mut res = BigUint::one();
    for _ in 0..e {
        res *= x;
    }
    res
}

/// Extension trait adding FF1-relevant methods to `BigUint`.
trait Numeral {
    /// Type used for byte representations.
    type Bytes: AsRef<[u8]>;

    /// Returns the integer interpreted from the given bytes in big-endian order.
    fn from_bytes(s: impl Iterator<Item = u8>) -> Self;

    /// Returns the big-endian byte representation of this integer.
    fn to_bytes(&self, b: usize) -> Self::Bytes;

    /// Compute (self + other) mod radix^m
    fn add_mod_exp(self, other: Self, radix: u32, m: usize) -> Self;

    /// Compute (self - other) mod radix^m
    fn sub_mod_exp(self, other: Self, radix: u32, m: usize) -> Self;
}

impl Numeral for BigUint {
    type Bytes = Vec<u8>;

    fn from_bytes(s: impl Iterator<Item = u8>) -> Self {
        BigUint::from_bytes_be(&s.collect::<Vec<_>>())
    }

    fn to_bytes(&self, b: usize) -> Vec<u8> {
        if self.is_zero() {
            // Because self.to_bytes_be() returns vec![0u8] for zero, instead of vec![], we would
            // end up with a subtraction overflow on empty input (since (b - bytes.len()) < 0 or
            // (0 - 1) < 0). This optimization side-steps that special case.
            vec![0; b]
        } else {
            let bytes = self.to_bytes_be();
            iter::repeat(0).take(b - bytes.len()).chain(bytes).collect()
        }
    }

    fn add_mod_exp(self, other: Self, radix: u32, m: usize) -> Self {
        (self + other) % pow(radix, m)
    }

    fn sub_mod_exp(self, other: Self, radix: u32, m: usize) -> Self {
        let modulus = BigInt::from(pow(radix, m));
        let mut c = (BigInt::from(self) - BigInt::from(other)) % &modulus;
        if c.sign() == Sign::Minus {
            // use ((x % m) + m) % m to ensure it is in range
            c += &modulus;
            c %= modulus;
        }
        c.to_biguint().unwrap()
    }
}

/// A numeral string that supports radixes in [2..2^16).
#[cfg_attr(test, derive(Debug))]
pub struct FlexibleNumeralString(Vec<u16>);

impl From<Vec<u16>> for FlexibleNumeralString {
    fn from(v: Vec<u16>) -> Self {
        FlexibleNumeralString(v)
    }
}

impl From<FlexibleNumeralString> for Vec<u16> {
    fn from(fns: FlexibleNumeralString) -> Self {
        fns.0
    }
}

impl NumeralString for FlexibleNumeralString {
    type Ops = Self;

    fn is_valid(&self, radix: u32) -> bool {
        self.0.iter().all(|n| (u32::from(*n) < radix))
    }

    fn numeral_count(&self) -> usize {
        self.0.len()
    }

    fn split(&self) -> (Self, Self) {
        let mut front = self.0.clone();
        let back = front.split_off(self.0.len() / 2);
        (FlexibleNumeralString(front), FlexibleNumeralString(back))
    }

    fn concat(mut a: Self, mut b: Self) -> Self {
        a.0.append(&mut b.0);
        a
    }
}

impl Operations for FlexibleNumeralString {
    type Bytes = Vec<u8>;

    fn numeral_count(&self) -> usize {
        self.0.len()
    }

    fn to_be_bytes(&self, radix: u32, b: usize) -> Self::Bytes {
        self.num_radix(radix).to_bytes(b)
    }

    fn add_mod_exp(self, other: impl Iterator<Item = u8>, radix: u32, m: usize) -> Self {
        let other = BigUint::from_bytes(other);
        let c = self.num_radix(radix).add_mod_exp(other, radix, m);
        Self::str_radix(c, radix, m)
    }

    fn sub_mod_exp(self, other: impl Iterator<Item = u8>, radix: u32, m: usize) -> Self {
        let other = BigUint::from_bytes(other);
        let c = self.num_radix(radix).sub_mod_exp(other, radix, m);
        Self::str_radix(c, radix, m)
    }
}

impl FlexibleNumeralString {
    fn num_radix(&self, radix: u32) -> BigUint {
        let mut res = BigUint::zero();
        for i in &self.0 {
            res *= radix;
            res += BigUint::from(*i);
        }
        res
    }

    fn str_radix(mut x: BigUint, radix: u32, m: usize) -> Self {
        let mut res = vec![0; m];
        for i in 0..m {
            res[m - 1 - i] = (&x % radix).to_u16().unwrap();
            x /= radix;
        }
        FlexibleNumeralString(res)
    }
}

/// A numeral string with radix 2.
#[cfg_attr(test, derive(Debug))]
pub struct BinaryNumeralString(Vec<u8>);

impl BinaryNumeralString {
    /// Creates a BinaryNumeralString from a byte slice, with each byte
    /// interpreted in little-endian bit order.
    pub fn from_bytes_le(s: &[u8]) -> Self {
        let mut data = Vec::with_capacity(s.len() * 8);
        for n in s {
            let mut tmp = *n;
            for _ in 0..8 {
                data.push(tmp & 1);
                tmp >>= 1;
            }
        }
        BinaryNumeralString(data)
    }

    /// Returns a Vec<u8>, with each byte written from the BinaryNumeralString
    /// in little-endian bit order.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        // We should always have a multiple of eight bits
        assert_eq!((self.0.len() + 7) / 8, self.0.len() / 8);
        let mut data = Vec::with_capacity(self.0.len() / 8);
        let mut acc = 0;
        let mut shift = 0;
        for n in &self.0 {
            acc += n << shift;
            shift += 1;
            if shift == 8 {
                data.push(acc);
                acc = 0;
                shift = 0;
            }
        }
        data
    }
}

impl NumeralString for BinaryNumeralString {
    type Ops = BinaryOps;

    fn is_valid(&self, radix: u32) -> bool {
        self.0.iter().all(|n| (u32::from(*n) < radix))
    }

    fn numeral_count(&self) -> usize {
        self.0.len()
    }

    fn split(&self) -> (Self::Ops, Self::Ops) {
        let n = self.numeral_count();
        let u = n / 2;
        let v = n - u;
        let mut front = self.0.clone();
        let back = front.split_off(u);
        (BinaryOps::new(front, u), BinaryOps::new(back, v))
    }

    fn concat(mut a: Self::Ops, mut b: Self::Ops) -> Self {
        a.data.append(&mut b.data);
        BinaryNumeralString(a.data)
    }
}

pub struct BinaryOps {
    data: Vec<u8>,
    num_bits: usize,
}

impl Operations for BinaryOps {
    type Bytes = Vec<u8>;

    fn numeral_count(&self) -> usize {
        self.num_bits
    }

    fn to_be_bytes(&self, radix: u32, b: usize) -> Self::Bytes {
        self.num_radix(radix).to_bytes(b)
    }

    fn add_mod_exp(self, other: impl Iterator<Item = u8>, radix: u32, m: usize) -> Self {
        assert_eq!(self.num_bits, m);
        let other = BigUint::from_bytes(other);
        let c = self.num_radix(radix).add_mod_exp(other, radix, m);
        Self::str_radix(c, radix, m)
    }

    fn sub_mod_exp(self, other: impl Iterator<Item = u8>, radix: u32, m: usize) -> Self {
        assert_eq!(self.num_bits, m);
        let other = BigUint::from_bytes(other);
        let c = self.num_radix(radix).sub_mod_exp(other, radix, m);
        Self::str_radix(c, radix, m)
    }
}

impl BinaryOps {
    fn new(data: Vec<u8>, num_bits: usize) -> Self {
        BinaryOps { data, num_bits }
    }

    fn num_radix(&self, radix: u32) -> BigUint {
        let zero = BigUint::zero();
        let one = BigUint::one();
        // Check that radix == 2
        assert_eq!(radix, 2);
        let mut res = zero;
        for i in &self.data {
            res <<= 1;
            if *i != 0 {
                res += &one;
            }
        }
        res
    }

    fn str_radix(mut x: BigUint, radix: u32, m: usize) -> Self {
        // Check that radix == 2
        assert_eq!(radix, 2);
        let mut res = vec![0; m];
        for i in 0..m {
            if x.is_odd() {
                res[m - 1 - i] = 1;
            }
            x >>= 1;
        }
        BinaryOps::new(res, m)
    }
}

#[cfg(test)]
mod tests {
    use aes::{Aes128, Aes192, Aes256};

    use super::{BinaryNumeralString, FlexibleNumeralString};
    use crate::ff1::{
        test_vectors::{self, AesType},
        NumeralString, NumeralStringError, FF1,
    };

    #[test]
    fn ns_is_valid() {
        let radix = 10;
        let ns = FlexibleNumeralString::from(vec![0, 5, 9]);
        assert!(ns.is_valid(radix));

        let ns = FlexibleNumeralString::from(vec![0, 5, 10]);
        assert!(!ns.is_valid(radix));
    }

    #[test]
    fn radix_2_length_limits() {
        let ff = FF1::<Aes128>::new(&[0; 16], 2).unwrap();

        assert_eq!(
            ff.encrypt(&[], &BinaryNumeralString::from_bytes_le(&[]))
                .unwrap_err(),
            NumeralStringError::TooShort {
                ns_len: 0,
                min_len: 20,
            },
        );
        assert_eq!(
            ff.encrypt(&[], &BinaryNumeralString::from_bytes_le(&[0]))
                .unwrap_err(),
            NumeralStringError::TooShort {
                ns_len: 8,
                min_len: 20,
            },
        );
        assert_eq!(
            ff.encrypt(&[], &BinaryNumeralString::from_bytes_le(&[0; 2]))
                .unwrap_err(),
            NumeralStringError::TooShort {
                ns_len: 16,
                min_len: 20,
            },
        );
        assert!(ff
            .encrypt(&[], &BinaryNumeralString::from_bytes_le(&[0; 3]))
            .is_ok());
    }

    #[test]
    fn radix_10_length_limits() {
        let ff = FF1::<Aes128>::new(&[0; 16], 10).unwrap();

        assert_eq!(
            ff.encrypt(&[], &FlexibleNumeralString::from(vec![]))
                .unwrap_err(),
            NumeralStringError::TooShort {
                ns_len: 0,
                min_len: 6,
            },
        );
        assert_eq!(
            ff.encrypt(&[], &FlexibleNumeralString::from(vec![0]))
                .unwrap_err(),
            NumeralStringError::TooShort {
                ns_len: 1,
                min_len: 6,
            },
        );
        assert_eq!(
            ff.encrypt(&[], &FlexibleNumeralString::from(vec![0; 2]))
                .unwrap_err(),
            NumeralStringError::TooShort {
                ns_len: 2,
                min_len: 6,
            },
        );
        assert_eq!(
            ff.encrypt(&[], &FlexibleNumeralString::from(vec![0; 5]))
                .unwrap_err(),
            NumeralStringError::TooShort {
                ns_len: 5,
                min_len: 6,
            },
        );
        assert!(ff
            .encrypt(&[], &FlexibleNumeralString::from(vec![0; 6]))
            .is_ok());
    }

    #[test]
    fn flexible_split_round_trip() {
        for tv in test_vectors::get() {
            {
                let pt = FlexibleNumeralString::from(tv.pt.clone());
                let (a, b) = pt.split();
                assert_eq!(FlexibleNumeralString::concat(a, b).0, tv.pt);
            }

            {
                let ct = FlexibleNumeralString::from(tv.ct.clone());
                let (a, b) = ct.split();
                assert_eq!(FlexibleNumeralString::concat(a, b).0, tv.ct);
            }
        }
    }

    #[test]
    fn flexible() {
        for tv in test_vectors::get() {
            let (ct, pt) = match tv.aes {
                AesType::AES128 => {
                    let ff = FF1::<Aes128>::new(&tv.key, tv.radix).unwrap();
                    (
                        ff.encrypt(&tv.tweak, &FlexibleNumeralString::from(tv.pt.clone())),
                        ff.decrypt(&tv.tweak, &FlexibleNumeralString::from(tv.ct.clone())),
                    )
                }
                AesType::AES192 => {
                    let ff = FF1::<Aes192>::new(&tv.key, tv.radix).unwrap();
                    (
                        ff.encrypt(&tv.tweak, &FlexibleNumeralString::from(tv.pt.clone())),
                        ff.decrypt(&tv.tweak, &FlexibleNumeralString::from(tv.ct.clone())),
                    )
                }
                AesType::AES256 => {
                    let ff = FF1::<Aes256>::new(&tv.key, tv.radix).unwrap();
                    (
                        ff.encrypt(&tv.tweak, &FlexibleNumeralString::from(tv.pt.clone())),
                        ff.decrypt(&tv.tweak, &FlexibleNumeralString::from(tv.ct.clone())),
                    )
                }
            };
            assert_eq!(Vec::from(ct.unwrap()), tv.ct);
            assert_eq!(Vec::from(pt.unwrap()), tv.pt);
        }
    }

    #[test]
    fn binary_split_round_trip() {
        for tv in test_vectors::get().filter(|tv| tv.binary.is_some()) {
            let tvb = tv.binary.unwrap();

            {
                let pt = BinaryNumeralString::from_bytes_le(&tvb.pt);
                let (a, b) = pt.split();
                assert_eq!(BinaryNumeralString::concat(a, b).to_bytes_le(), tvb.pt);
            }

            {
                let ct = BinaryNumeralString::from_bytes_le(&tvb.ct);
                let (a, b) = ct.split();
                assert_eq!(BinaryNumeralString::concat(a, b).to_bytes_le(), tvb.ct);
            }
        }
    }

    #[test]
    fn binary() {
        for tv in test_vectors::get().filter(|tv| tv.binary.is_some()) {
            assert_eq!(tv.aes, AesType::AES256);

            let tvpt = tv.pt.iter().map(|b| *b as u8).collect::<Vec<_>>();
            let tvct = tv.ct.iter().map(|b| *b as u8).collect::<Vec<_>>();
            let tvb = tv.binary.unwrap();

            let (ct, pt, bct, bpt) = {
                let ff = FF1::<Aes256>::new(&tv.key, tv.radix).unwrap();
                (
                    ff.encrypt(&tv.tweak, &BinaryNumeralString(tvpt.clone()))
                        .unwrap(),
                    ff.decrypt(&tv.tweak, &BinaryNumeralString(tvct.clone()))
                        .unwrap(),
                    ff.encrypt(&tv.tweak, &BinaryNumeralString::from_bytes_le(&tvb.pt))
                        .unwrap(),
                    ff.decrypt(&tv.tweak, &BinaryNumeralString::from_bytes_le(&tvb.ct))
                        .unwrap(),
                )
            };
            assert_eq!(pt.to_bytes_le(), tvb.pt);
            assert_eq!(ct.to_bytes_le(), tvb.ct);
            assert_eq!(bpt.to_bytes_le(), tvb.pt);
            assert_eq!(bct.to_bytes_le(), tvb.ct);
            assert_eq!(pt.0, tvpt);
            assert_eq!(ct.0, tvct);
            assert_eq!(bpt.0, tvpt);
            assert_eq!(bct.0, tvct);
        }
    }
}
