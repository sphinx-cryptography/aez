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
                ad.as_ptr(),
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
                ad.as_ptr(),
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
