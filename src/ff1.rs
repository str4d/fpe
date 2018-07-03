use aes::{block_cipher_trait::generic_array::GenericArray, Aes128, BlockCipher};
use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::{identities::Zero, ToPrimitive};

// radix in [2..2^16]
type Radix = u16;

fn num_radix(x: &[Radix], radix: Radix) -> BigUint {
    let mut res = BigUint::zero();
    let base = BigUint::from(radix);
    for i in x {
        res *= &base;
        res += BigUint::from(*i);
    }
    res
}

fn str_radix(mut x: BigUint, radix: Radix, m: usize) -> Vec<Radix> {
    let mut res = vec![0; m];
    for i in 0..m {
        res[m - 1 - i] = (&x % radix).to_u16().unwrap();
        x = x / radix;
    }
    res
}

pub struct FF1 {
    ciph: Aes128,
    radix: Radix,
}

impl FF1 {
    fn prf(&self, x: &[u8]) -> [u8; 16] {
        let m = x.len() / 16;
        let mut y = [0u8; 16];
        for j in 0..m {
            for i in 0..16 {
                y[i] ^= x[j * 16 + i];
            }
            self.ciph
                .encrypt_block(&mut GenericArray::from_mut_slice(&mut y));
        }
        y
    }

    pub fn new(key: &[u8], radix: Radix) -> Self {
        let ciph = Aes128::new(GenericArray::from_slice(key));
        FF1 { ciph, radix }
    }

    pub fn encrypt(&self, tweak: &[u8], x: &[Radix]) -> Vec<Radix> {
        let n = x.len();
        let t = tweak.len();

        // 1. Let u = floor(n / 2); v = n - u
        let u = n / 2;
        let v = n - u;

        // 2. Let A = X[1..u]; B = X[u + 1..n].
        let mut x_a = Vec::from(&x[0..u]);
        let mut x_b = Vec::from(&x[u..n]);

        // 3. Let b = ceil(ceil(v * log2(radix)) / 8).
        let b = (v as f64 * (self.radix as f64).log2() / 8f64).ceil() as usize;

        // 4. Let d = 4 * ceil(b / 4) + 4.
        let d = (4f64 * (b as f64 / 4f64).ceil() + 4f64) as usize;

        // 5. Let P = [1, 2, 1] || [radix] || [10] || [u mod 256] || [n] || [t].
        let mut p = vec![1, 2, 1];
        p.write_u24::<BigEndian>(self.radix as u32).unwrap();
        p.write_u8(10).unwrap();
        p.write_u8(u as u8).unwrap();
        p.write_u32::<BigEndian>(n as u32).unwrap();
        p.write_u32::<BigEndian>(t as u32).unwrap();

        //  6i. Let Q = T || [0]^((-t-b-1) mod 16) || [i] || [NUM(B, radix)].
        let q_base = {
            let val = ((((-(t as i32) - (b as i32) - 1) % 16) + 16) % 16) as usize;
            let mut q = Vec::from(tweak);
            q.resize(t + val, 0);
            q
        };
        for i in 0..10 {
            let mut q = q_base.clone();
            q.write_u8(i).unwrap();
            let q_bytes = num_radix(&x_b, self.radix).to_bytes_be();
            for _ in 0..(b - q_bytes.len()) {
                q.write_u8(0).unwrap();
            }
            q.extend(q_bytes);

            // 6ii. Let R = PRF(P || Q).
            let r = self.prf(&[&p[..], &q[..]].concat());

            // 6iii. Let S be the first d bytes of R.
            assert!(d <= 16); // TODO Handle d > 16
            let s = &r[..d];

            // 6iv. Let y = NUM(S).
            let y = BigUint::from_bytes_be(s);

            // 6v. If i is even, let m = u; else, let m = v.
            let m = if i % 2 == 0 { u } else { v };

            // 6vi. Let c = (NUM(A, radix) + y) mod radix^m.
            let c = (num_radix(&x_a, self.radix) + y) % (self.radix as u64).pow(m as u32);

            // 6vii. Let C = STR(c, radix).
            let x_c = str_radix(c, self.radix, m);

            // 6viii. Let A = B.
            x_a = x_b;

            // 6ix. Let B = C.
            x_b = x_c;
        }

        // 7. Return A || B.
        [x_a, x_b].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::{FF1, Radix};

    #[test]
    fn test_vectors() {
        struct TestVector {
            key: Vec<u8>,
            radix: Radix,
            tweak: Vec<u8>,
            pt: Vec<Radix>,
            ct: Vec<Radix>,
        };

        let test_vectors = vec![
            // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF1samples.pdf
            TestVector {
                // Sample #1
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C,
                ],
                radix: 10,
                tweak: vec![],
                pt: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                ct: vec![2, 4, 3, 3, 4, 7, 7, 4, 8, 4],
            },
            TestVector {
                // Sample #2
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C,
                ],
                radix: 10,
                tweak: vec![0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30],
                pt: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                ct: vec![6, 1, 2, 4, 2, 0, 0, 7, 7, 3],
            },
            TestVector {
                // Sample #3
                key: vec![
                    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09,
                    0xCF, 0x4F, 0x3C,
                ],
                radix: 36,
                tweak: vec![
                    0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37,
                ],
                pt: vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
                ],
                ct: vec![
                    10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22,
                ],
            },
        ];

        for tv in test_vectors {
            let ff = FF1::new(&tv.key, tv.radix);
            assert_eq!(ff.encrypt(&tv.tweak, &tv.pt[..]), tv.ct);
        }
    }
}
