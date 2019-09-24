use aez::Aez;

const TEST_VECTORS: &str = include_str!("encrypt_no_ad.json");

#[derive(serde_derive::Deserialize)]
struct TestCase {
    k: String,
    nonce: String,
    // unused
    _data: Vec<String>,
    // must equal c.len() - m.len()
    tau: u32,
    m: String,
    c: String,
}

#[test]
fn vectors() {
    let mut ct = Vec::new();
    let mut pt = Vec::new();

    for TestCase {
        k, nonce, tau, m, c, ..
    } in serde_json::from_str::<Vec<TestCase>>(TEST_VECTORS).unwrap()
    {
        eprintln!("Testing: k={}, n={}, m={}, c={}", k, nonce, m, c);

        let n = hex::decode(nonce).expect("nonce contains invalid hex");
        let k = hex::decode(k).expect("key contains invalid hex");
        let m = hex::decode(m).expect("message contains invalid hex");
        let c = hex::decode(c).expect("ciphertext contains invalid hex");
        assert_eq!(tau as usize, c.len() - m.len(), "invalid test vector");

        pt.clear();
        pt.resize(m.len(), 0);
        ct.clear();
        ct.resize(c.len(), 0);

        let cipher = Aez::new(&k);

        cipher.encrypt(&n, &[], &m, &mut ct);
        assert_eq!(ct, c);
        assert!(
            cipher.decrypt(&n, &[], &c, &mut pt).is_ok(),
            "decryption failed"
        );
        assert_eq!(pt, m);
    }
}
