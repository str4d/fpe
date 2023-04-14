use aes::Aes256;

use crate::ff1::{BinaryNumeralString, FF1h};

#[test]
fn test_doc_example_18_rounds() {
    let key = [0; 32];
    let radix = 2;
    let pt = [0xab, 0xcd, 0xef];

    let ff = FF1h::<Aes256>::new(&key, radix).unwrap();
    let ct = ff
        .encrypt(&[], &BinaryNumeralString::from_bytes_le(&pt))
        .unwrap();
    assert_eq!(ct.to_bytes_le(), [0x5a, 0x6c, 0x20]);

    let p2 = ff.decrypt(&[], &ct).unwrap();
    assert_eq!(p2.to_bytes_le(), pt);
}
