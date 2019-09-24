// tests/vectors.rs - aez test vectors
// Copyright (C) 2019  Katzenpost Developers
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use aez::Aez;

const TEST_VECTORS: &str = include_str!("aez.json");

#[derive(serde_derive::Deserialize)]
struct TestCase<'a> {
    k: &'a str,
    nonce: &'a str,
    // unused
    data: Vec<&'a str>,
    // must equal c.len() - m.len()
    tau: u32,
    m: &'a str,
    c: &'a str,
}

#[test]
fn vectors() {
    for TestCase {
        k,
        nonce,
        data,
        tau,
        m,
        c,
    } in serde_json::from_str::<Vec<TestCase>>(TEST_VECTORS).unwrap()
    {
        eprintln!("test start");

        let n = hex::decode(nonce).expect("nonce contains invalid hex");
        let k = hex::decode(k).expect("key contains invalid hex");
        let m = hex::decode(m).expect("message contains invalid hex");
        let aad = data
            .into_iter()
            .map(|d| hex::decode(d).expect("data contains invalid hex"))
            .collect::<Vec<Vec<u8>>>();
        let c = hex::decode(c).expect("ciphertext contains invalid hex");
        assert_eq!(tau as usize, c.len() - m.len(), "invalid test vector");

        let cipher = Aez::new(&k);

        let aad = match aad.len() {
            0 => &[][..],
            1 => &aad[0],
            n => {
                eprintln!("skipping AAD test with {} parts", n);
                continue;
            }
        };

        let mut ct = vec![0u8; c.len()];
        let mut pt = vec![0u8; m.len()];

        cipher.encrypt(&n, aad, &m, &mut ct);
        assert_eq!(ct, c);
        assert!(
            cipher.decrypt(&n, aad, &c, &mut pt).is_ok(),
            "decryption failed"
        );
        assert_eq!(pt, m);
    }
}
