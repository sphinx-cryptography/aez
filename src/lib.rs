// src/lib.rs - aez C-to-Rust bindings
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

//! [AEZv5](https://web.cs.ucdavis.edu/~rogaway/aez).
//!
//! > AEZ is an authenticated-encryption (AE) scheme optimized for ease of correct
//! > use (“AE made EZ”). It was invented by Viet Tung Hoang, Ted Krovetz, and
//! > Phillip Rogaway. The algorithm encrypts a plaintext by appending to it a fixed
//! > authentication block (some zero bits) and then enciphering the resulting string
//! > with an arbitrary-input-length blockcipher, this tweaked by the nonce, AD, and
//! > authenticator length. The approach results in strong security and usability
//! > properties, including nonce-reuse misuse resistance, automatic exploitation of
//! > decryption-verified redundancy, and arbitrary, user-selectable length expansion.
//! > AEZ is parallelizable and its computational cost is roughly that of OCB. On recent
//! > Intel processors, AEZ runs at about 0.7 cpb.
//!
//! The C implementation is compiled assuming AES-NI support. There is no software fallback
//! implemented in this crate.
//!
//! ```
//! # use aez::Aez;
//! # let secret_key = [0u8; 48];
//! // The secret key may be any byte slice. 48 bytes are recommended.
//! let cipher = Aez::new(&secret_key);
//!
//! // Expand the ciphertext by 16 bytes for authentication.
//! let mut pt = b"Hello world!".to_vec();
//! let mut ct = vec![0u8; pt.len() + 16];
//!
//! // Encrypt the message with a nonce, and optionally additional data.
//! cipher.encrypt(&[0], None, &pt, &mut ct);
//!
//! // Decrypt and validate the ciphertext.
//! cipher.decrypt(&[0], None, &ct, &mut pt).expect("invalid ciphertext");
//!
//! // Message decrypted!
//! assert_eq!(pt, b"Hello world!");
//! ```

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("AEZ requires x86 or x86_64.");

#[repr(C)]
#[repr(align(16))]
pub struct Aez([u8; 144]);

extern "C" {
    fn aez_setup(key: *const u8, keylen: u32, ctx: &mut Aez);
    fn aez_encrypt(
        ctx: &Aez,
        n: *const u8,
        nbytes: u32,
        ad: *const u8,
        adbytes: u32,
        abytes: u32,
        src: *const u8,
        bytes: u32,
        dst: *mut u8,
    );
    fn aez_decrypt(
        ctx: &Aez,
        n: *const u8,
        nbytes: u32,
        ad: *const u8,
        adbytes: u32,
        abytes: u32,
        src: *const u8,
        bytes: u32,
        dst: *mut u8,
    ) -> isize;
}

impl Aez {
    /// Create a new Aez instance keyed with variable length. Aez recommends a 48 byte key.
    pub fn new(key: &[u8]) -> Self {
        let mut aez = Aez([0u8; 144]);

        unsafe {
            aez_setup(key.as_ptr(), key.len() as u32, &mut aez);
        }

        aez
    }

    /// Encrypt a message. The nonce length must be `1..=16`. The ciphertext may be up to 16 bytes
    /// larger than the message, these extra bytes add authentication. Additionally, the ciphertext
    /// must not be larger than `2^32 - 1`.
    ///
    /// Will panic if the above constraints are broken.
    pub fn encrypt<'a>(&self, n: &[u8], ad: impl Into<Option<&'a [u8]>>, pt: &[u8], ct: &mut [u8]) {
        assert!(
            ct.len() >= pt.len(),
            "Ciphertext must not be smaller than the plaintext."
        );
        assert!(ct.len() < core::u32::MAX as usize, "ciphertext length too long");
        assert!(
            ct.len() - pt.len() <= 16,
            "tau is bounded up to 16 for this C implementation."
        );
        assert!(n.len() > 0, "Nonce must not have length zero.");

        let ad = ad.into();

        unsafe {
            aez_encrypt(
                self,
                n.as_ptr(),
                n.len() as u32,
                if let Some(ad) = ad {
                    ad.as_ptr()
                } else {
                    core::ptr::null()
                },
                if let Some(ad) = ad {
                    ad.len() as u32
                } else {
                    0
                },
                ct.len() as u32 - pt.len() as u32,
                pt.as_ptr(),
                pt.len() as u32,
                ct.as_mut_ptr(),
            );
        }
    }

    /// Decrypt a message. The nonce length must be `1..=16`. The ciphertext may be up to 16 bytes
    /// larger than the message, these extra bytes add authentication. Additionally, the ciphertext
    /// must not be larger than `2^32 - 1`.
    ///
    /// Will panic if the above constraints are broken.
    pub fn decrypt<'a>(
        &self,
        n: &[u8],
        ad: impl Into<Option<&'a [u8]>>,
        ct: &[u8],
        pt: &mut [u8],
    ) -> Result<(), ()> {
        assert!(
            ct.len() >= pt.len(),
            "Ciphertext must not be smaller than the plaintext."
        );
        assert!(ct.len() < core::u32::MAX as usize, "ciphertext length too long");
        assert!(
            ct.len() - pt.len() <= 16,
            "tau is bounded up to 16 for this C implementation."
        );
        assert!(n.len() != 0 && n.len() <= 16, "invalid nonce");

        let ad = ad.into();

        match unsafe {
            aez_decrypt(
                self,
                n.as_ptr(),
                n.len() as u32,
                if let Some(ad) = ad {
                    ad.as_ptr()
                } else {
                    core::ptr::null()
                },
                if let Some(ad) = ad {
                    ad.len() as u32
                } else {
                    0
                },
                ct.len() as u32 - pt.len() as u32,
                ct.as_ptr(),
                ct.len() as u32,
                pt.as_mut_ptr(),
            )
        } {
            0 => Ok(()),
            _ => Err(()),
        }
    }
}
