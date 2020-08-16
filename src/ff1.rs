//! A Rust implementation of the FF1 algorithm, specified in
//! [NIST Special Publication 800-38G](http://dx.doi.org/10.6028/NIST.SP.800-38G).

use aes::block_cipher::{generic_array::GenericArray, Block, BlockCipher, NewBlockCipher};
use block_modes::{block_padding::NoPadding, BlockMode, Cbc};
use std::cmp;

mod alloc;
pub use alloc::{BinaryNumeralString, FlexibleNumeralString};

#[derive(Debug, PartialEq)]
enum Radix {
    /// A radix in [2..2^16]. It uses floating-point arithmetic.
    Any(u32),
    /// A radix 2^i for i in [1..16]. It does not use floating-point arithmetic.
    PowerTwo { radix: u32, log_radix: u8 },
}

impl Radix {
    pub fn from(radix: u32) -> Result<Self, ()> {
        // radix must be in range [2..2^16]
        if radix < 2 || radix > (1 << 16) {
            return Err(());
        }

        let mut tmp = radix;
        let mut log_radix = None;
        let mut found_bit = false;

        // 2^16 is 17 bits
        for i in 0..17 {
            if tmp & 1 != 0 {
                // Only a single bit can be set for PowerTwo
                if found_bit {
                    log_radix = None;
                } else {
                    log_radix = Some(i);
                    found_bit = true;
                }
            }
            tmp >>= 1;
        }
        Ok(match log_radix {
            Some(log_radix) => Radix::PowerTwo { radix, log_radix },
            None => Radix::Any(radix),
        })
    }

    /// Calculates b = ceil(ceil(v * log2(radix)) / 8).
    fn calculate_b(&self, v: usize) -> usize {
        match *self {
            Radix::Any(r) => (v as f64 * f64::from(r).log2() / 8f64).ceil() as usize,
            Radix::PowerTwo { log_radix, .. } => ((v * log_radix as usize) + 7) / 8,
        }
    }

    fn to_u32(&self) -> u32 {
        match *self {
            Radix::Any(r) => r,
            Radix::PowerTwo { radix, .. } => radix,
        }
    }
}

/// An integer.
pub trait Numeral {
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

/// For a given base, a finite, ordered sequence of numerals for the base.
pub trait NumeralString: Sized {
    /// The type used for numeric operations.
    type Num: Numeral;

    /// Returns whether this numeral string is valid for the base radix.
    fn is_valid(&self, radix: u32) -> bool;

    /// Returns the number of numerals in this numeral string.
    fn len(&self) -> usize;

    /// Splits this numeral string into two sections X[..u] and X[u..].
    fn split(&self, u: usize) -> (Self, Self);

    /// Concatenates two numeral strings.
    fn concat(a: Self, b: Self) -> Self;

    /// The number that this numeral string represents in the base radix
    /// when the numerals are valued in decreasing order of significance
    /// (big-endian order).
    fn num_radix(&self, radix: u32) -> Self::Num;

    /// Given a non-negative integer x less than radix<sup>m</sup>, returns
    /// the representation of x as a string of m numerals in base radix,
    /// in decreasing order of significance (big-endian order).
    fn str_radix(x: Self::Num, radix: u32, m: usize) -> Self;
}

#[derive(Clone)]
struct Prf<CIPH: NewBlockCipher + BlockCipher> {
    state: Cbc<CIPH, NoPadding>,
    // Contains the output when offset = 0, and partial input otherwise
    buf: [Block<CIPH>; 1],
    offset: usize,
}

impl<CIPH: NewBlockCipher + BlockCipher + Clone> Prf<CIPH> {
    fn new(ciph: &CIPH) -> Self {
        let ciph = ciph.clone();
        Prf {
            state: Cbc::new(ciph, GenericArray::from_slice(&[0; 16])),
            buf: [Block::<CIPH>::default()],
            offset: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let to_read = cmp::min(self.buf[0].len() - self.offset, data.len());
            self.buf[0][self.offset..self.offset + to_read].copy_from_slice(&data[..to_read]);
            self.offset += to_read;
            data = &data[to_read..];

            if self.offset == self.buf[0].len() {
                self.state.encrypt_blocks(&mut self.buf);
                self.offset = 0;
            }
        }
    }

    /// Returns the current PRF output.
    ///
    /// The caller MUST ensure that the PRF has processed an integer number of blocks.
    fn output(&self) -> &Block<CIPH> {
        assert_eq!(self.offset, 0);
        &self.buf[0]
    }
}

fn generate_s<'a, CIPH: BlockCipher>(
    ciph: &'a CIPH,
    r: &'a Block<CIPH>,
    d: usize,
) -> impl Iterator<Item = u8> + 'a {
    r.clone()
        .into_iter()
        .chain((1..((d + 15) / 16) as u128).flat_map(move |j| {
            let mut block = r.clone();
            for (b, j) in block.iter_mut().zip(j.to_be_bytes().iter()) {
                *b ^= j;
            }
            ciph.encrypt_block(&mut block);
            block.into_iter()
        }))
        .take(d)
}

/// A struct for performing FF1 encryption and decryption operations.
pub struct FF1<CIPH: BlockCipher> {
    ciph: CIPH,
    radix: Radix,
}

impl<CIPH: NewBlockCipher + BlockCipher + Clone> FF1<CIPH> {
    /// Creates a new FF1 object for the given key and radix.
    ///
    /// Returns an error if the given radix is not in [2..2^16].
    pub fn new(key: &[u8], radix: u32) -> Result<Self, ()> {
        let ciph = CIPH::new(GenericArray::from_slice(key));
        let radix = Radix::from(radix)?;
        Ok(FF1 { ciph, radix })
    }

    /// Encrypts the given numeral string.
    ///
    /// Returns an error if the numeral string is not in the required radix.
    pub fn encrypt<NS: NumeralString>(&self, tweak: &[u8], x: &NS) -> Result<NS, ()> {
        if !x.is_valid(self.radix.to_u32()) {
            return Err(());
        }

        let n = x.len();
        let t = tweak.len();

        // 1. Let u = floor(n / 2); v = n - u
        let u = n / 2;
        let v = n - u;

        // 2. Let A = X[1..u]; B = X[u + 1..n].
        let (mut x_a, mut x_b) = x.split(u);

        // 3. Let b = ceil(ceil(v * log2(radix)) / 8).
        let b = self.radix.calculate_b(v);

        // 4. Let d = 4 * ceil(b / 4) + 4.
        let d = 4 * ((b + 3) / 4) + 4;

        // 5. Let P = [1, 2, 1] || [radix] || [10] || [u mod 256] || [n] || [t].
        let mut p = [1, 2, 1, 0, 0, 0, 10, u as u8, 0, 0, 0, 0, 0, 0, 0, 0];
        p[3..6].copy_from_slice(&self.radix.to_u32().to_be_bytes()[1..]);
        p[8..12].copy_from_slice(&(n as u32).to_be_bytes());
        p[12..16].copy_from_slice(&(t as u32).to_be_bytes());

        //  6i. Let Q = T || [0]^((-t-b-1) mod 16) || [i] || [NUM(B, radix)].
        // 6ii. Let R = PRF(P || Q).
        let mut prf = Prf::new(&self.ciph);
        prf.update(&p);
        prf.update(tweak);
        for _ in 0..((((-(t as i32) - (b as i32) - 1) % 16) + 16) % 16) {
            prf.update(&[0]);
        }
        for i in 0..10 {
            let mut prf = prf.clone();
            prf.update(&[i]);
            prf.update(x_b.num_radix(self.radix.to_u32()).to_bytes(b).as_ref());
            let r = prf.output();

            // 6iii. Let S be the first d bytes of R.
            let s = generate_s(&self.ciph, r, d);

            // 6iv. Let y = NUM(S).
            let y = NS::Num::from_bytes(s);

            // 6v. If i is even, let m = u; else, let m = v.
            let m = if i % 2 == 0 { u } else { v };

            // 6vi. Let c = (NUM(A, radix) + y) mod radix^m.
            let c = x_a
                .num_radix(self.radix.to_u32())
                .add_mod_exp(y, self.radix.to_u32(), m);

            // 6vii. Let C = STR(c, radix).
            let x_c = NS::str_radix(c, self.radix.to_u32(), m);

            // 6viii. Let A = B.
            x_a = x_b;

            // 6ix. Let B = C.
            x_b = x_c;
        }

        // 7. Return A || B.
        Ok(NS::concat(x_a, x_b))
    }

    /// Decrypts the given numeral string.
    ///
    /// Returns an error if the numeral string is not in the required radix.
    pub fn decrypt<NS: NumeralString>(&self, tweak: &[u8], x: &NS) -> Result<NS, ()> {
        if !x.is_valid(self.radix.to_u32()) {
            return Err(());
        }

        let n = x.len();
        let t = tweak.len();

        // 1. Let u = floor(n / 2); v = n - u
        let u = n / 2;
        let v = n - u;

        // 2. Let A = X[1..u]; B = X[u + 1..n].
        let (mut x_a, mut x_b) = x.split(u);

        // 3. Let b = ceil(ceil(v * log2(radix)) / 8).
        let b = self.radix.calculate_b(v);

        // 4. Let d = 4 * ceil(b / 4) + 4.
        let d = 4 * ((b + 3) / 4) + 4;

        // 5. Let P = [1, 2, 1] || [radix] || [10] || [u mod 256] || [n] || [t].
        let mut p = [1, 2, 1, 0, 0, 0, 10, u as u8, 0, 0, 0, 0, 0, 0, 0, 0];
        p[3..6].copy_from_slice(&self.radix.to_u32().to_be_bytes()[1..]);
        p[8..12].copy_from_slice(&(n as u32).to_be_bytes());
        p[12..16].copy_from_slice(&(t as u32).to_be_bytes());

        //  6i. Let Q = T || [0]^((-t-b-1) mod 16) || [i] || [NUM(A, radix)].
        // 6ii. Let R = PRF(P || Q).
        let mut prf = Prf::new(&self.ciph);
        prf.update(&p);
        prf.update(tweak);
        for _ in 0..((((-(t as i32) - (b as i32) - 1) % 16) + 16) % 16) {
            prf.update(&[0]);
        }
        for i in 0..10 {
            let i = 9 - i;
            let mut prf = prf.clone();
            prf.update(&[i]);
            prf.update(x_a.num_radix(self.radix.to_u32()).to_bytes(b).as_ref());
            let r = prf.output();

            // 6iii. Let S be the first d bytes of R.
            let s = generate_s(&self.ciph, r, d);

            // 6iv. Let y = NUM(S).
            let y = NS::Num::from_bytes(s);

            // 6v. If i is even, let m = u; else, let m = v.
            let m = if i % 2 == 0 { u } else { v };

            // 6vi. Let c = (NUM(B, radix) - y) mod radix^m.
            let c = x_b
                .num_radix(self.radix.to_u32())
                .sub_mod_exp(y, self.radix.to_u32(), m);

            // 6vii. Let C = STR(c, radix).
            let x_c = NS::str_radix(c, self.radix.to_u32(), m);

            // 6viii. Let B = A.
            x_b = x_a;

            // 6ix. Let A = C.
            x_a = x_c;
        }

        // 7. Return A || B.
        Ok(NS::concat(x_a, x_b))
    }
}

#[cfg(test)]
mod tests {
    use super::Radix;

    #[test]
    fn radix() {
        assert_eq!(Radix::from(1), Err(()));
        assert_eq!(
            Radix::from(2),
            Ok(Radix::PowerTwo {
                radix: 2,
                log_radix: 1,
            })
        );
        assert_eq!(Radix::from(3), Ok(Radix::Any(3)));
        assert_eq!(
            Radix::from(4),
            Ok(Radix::PowerTwo {
                radix: 4,
                log_radix: 2,
            })
        );
        assert_eq!(Radix::from(5), Ok(Radix::Any(5)));
        assert_eq!(Radix::from(6), Ok(Radix::Any(6)));
        assert_eq!(Radix::from(7), Ok(Radix::Any(7)));
        assert_eq!(
            Radix::from(8),
            Ok(Radix::PowerTwo {
                radix: 8,
                log_radix: 3,
            })
        );
        assert_eq!(
            Radix::from(32768),
            Ok(Radix::PowerTwo {
                radix: 32768,
                log_radix: 15,
            })
        );
        assert_eq!(Radix::from(65535), Ok(Radix::Any(65535)));
        assert_eq!(
            Radix::from(65536),
            Ok(Radix::PowerTwo {
                radix: 65536,
                log_radix: 16,
            })
        );
        assert_eq!(Radix::from(65537), Err(()));
    }
}
