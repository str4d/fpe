//! FF1 NumeralString implementations that require a global allocator.

use core::iter;

use alloc::{vec, vec::Vec};

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{
    identities::{One, Zero},
    ToPrimitive,
};

use super::{Numeral, NumeralString};

fn pow(x: u32, e: usize) -> BigUint {
    let mut res = BigUint::one();
    for _ in 0..e {
        res *= x;
    }
    res
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
    type Num = BigUint;

    fn is_valid(&self, radix: u32) -> bool {
        self.0.iter().all(|n| (u32::from(*n) < radix))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn split(&self, u: usize) -> (Self, Self) {
        let mut front = self.0.clone();
        let back = front.split_off(u);
        (FlexibleNumeralString(front), FlexibleNumeralString(back))
    }

    fn concat(mut a: Self, mut b: Self) -> Self {
        a.0.append(&mut b.0);
        a
    }

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
    type Num = BigUint;

    fn is_valid(&self, radix: u32) -> bool {
        self.0.iter().all(|n| (u32::from(*n) < radix))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn split(&self, u: usize) -> (Self, Self) {
        let mut front = self.0.clone();
        let back = front.split_off(u);
        (BinaryNumeralString(front), BinaryNumeralString(back))
    }

    fn concat(mut a: Self, mut b: Self) -> Self {
        a.0.append(&mut b.0);
        a
    }

    fn num_radix(&self, radix: u32) -> BigUint {
        let zero = BigUint::zero();
        let one = BigUint::one();
        // Check that radix == 2
        assert_eq!(radix, 2);
        let mut res = zero;
        for i in &self.0 {
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
        BinaryNumeralString(res)
    }
}

#[cfg(test)]
mod tests {
    use aes::{Aes128, Aes192, Aes256};

    use super::{BinaryNumeralString, FlexibleNumeralString};
    use crate::ff1::{
        test_vectors::{self, AesType},
        NumeralString, FF1,
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
