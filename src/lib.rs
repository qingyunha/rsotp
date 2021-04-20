#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_mut)]

mod base32;
mod sha1;

struct OTP {
    secret: String,
    digits: u8,
    digest: String,
    name: String,
    issuer: String,
}

impl OTP {
    fn new(secret: String) -> OTP {
        OTP {
            secret: secret,
            digits: 6,
            digest: String::from("sha1"),
            name: String::new(),
            issuer: String::new(),
        }
    }

    fn generate_otp(&self, input: u64) -> String {
        let h = sha1::hmac_sha1(&self.byte_secret(), &self.int_to_bytes(input));
        let offset = h[19] as usize & 0x0f;
        let code = (h[offset] as u32 & 0x7f) << 24 |
            (h[offset + 1] as u32 & 0xff) << 16 |
            (h[offset + 2] as u32 & 0xff) << 8 |
            (h[offset + 3] as u32 & 0xff);
        let code = code % 10u32.pow(self.digits as u32);
        let mut r = code.to_string();
        let pending = ['0' as u8; 10];
        let i = self.digits as usize - r.len();
        use std::str;
        r.insert_str(0, str::from_utf8(&pending[..i]).unwrap());
        r
    }

    fn byte_secret(&self) -> Vec<u8> {
        base32::decode(&self.secret)
    }

    fn int_to_bytes(&self, v: u64) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = (v >> 56) as u8;
        b[1] = (v >> 48) as u8;
        b[2] = (v >> 40) as u8;
        b[3] = (v >> 32) as u8;
        b[4] = (v >> 24) as u8;
        b[5] = (v >> 16) as u8;
        b[6] = (v >> 8) as u8;
        b[7] = v as u8;
        b
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_otp() {
        let otp = super::OTP::new(String::from("3O75UXLUVM5NE3HA"));
        assert_eq!(otp.generate_otp(123), "276083");
        assert_eq!(otp.generate_otp(0), "463950");
        assert_eq!(otp.generate_otp(9), "003954");
    }
}
