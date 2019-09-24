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
    pub fn new(key: &[u8]) -> Self {
        let mut aez = Aez([0u8; 144]);

        unsafe {
            aez_setup(key.as_ptr(), key.len() as u32, &mut aez);
        }

        aez
    }

    pub fn encrypt(&self, n: &[u8], ad: &[u8], pt: &[u8], ct: &mut [u8]) {
        assert!(
            ct.len() >= pt.len(),
            "Ciphertext must not be smaller than the plaintext."
        );
        assert!(n.len() > 0, "Nonce must not have length zero.");

        unsafe {
            aez_encrypt(
                self,
                n.as_ptr(),
                n.len() as u32,
                if ad.len() == 0 { core::ptr::null() } else { ad.as_ptr() },
                ad.len() as u32,
                ct.len() as u32 - pt.len() as u32,
                pt.as_ptr(),
                pt.len() as u32,
                ct.as_mut_ptr(),
            );
        }
    }

    pub fn decrypt(&self, n: &[u8], ad: &[u8], ct: &[u8], pt: &mut [u8]) -> Result<(), ()> {
        assert!(
            ct.len() >= pt.len(),
            "Ciphertext must not be smaller than the plaintext."
        );
        assert!(n.len() > 0, "Nonce must not have length zero.");

        match unsafe {
            aez_decrypt(
                self,
                n.as_ptr(),
                n.len() as u32,
                if ad.len() == 0 { core::ptr::null() } else { ad.as_ptr() },
                ad.len() as u32,
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
