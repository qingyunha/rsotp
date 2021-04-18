const K0:u32 = 0x5A827999;
const K1:u32 = 0x6ED9EBA1;
const K2:u32 = 0x8F1BBCDC;
const K3:u32 = 0xCA62C1D6;


pub fn sha1(p : &[u8]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) = (0x67452301u32, 0xEFCDAB89u32, 0x98BADCFEu32, 0x10325476u32, 0xC3D2E1F0u32);
    let len = p.len();
    let mut tmp = [0u8; 64];
    tmp[0] = 0x80;
    let i = if len % 64 < 56 {
        56-len%64
    } else {
        64-len%64+56
    };
    let len = len << 3;
    putbigu64(&mut tmp[i..], len as u64);
    let i = i + 8;

    let mut w = [0u32; 16];
    let mut p = &p[..];
    let mut done = false;
    let mut lastblock;
    while !done {
        if p.len() < 64 {
            done = true;
            lastblock = [p, &tmp[..i]].concat();
            p = &lastblock;
        }
        for i in 0..16 {
                let j = i * 4;
                w[i] = (p[j] as u32)<<24 | (p[j+1] as u32)<<16 | (p[j+2] as u32)<<8 | (p[j+3] as u32);
        }

	let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        let mut i = 0;
        while i < 16 {
            // (B AND C) OR ((NOT B) AND D) 
            let f = b&c | (!b)&d;
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(w[i&0xf]).wrapping_add(K0);
            let (aa, bb, cc, dd, ee) = (t, a, b.rotate_left(30), c, d);
            a = aa; b = bb; c = cc; d = dd; e = ee;
            i += 1;
        }
        while i < 20 {
            let tmp = w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf];
            w[i&0xf] = tmp<<1 | tmp>>(32-1);
            let f = b&c | (!b)&d;
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(w[i&0xf]).wrapping_add(K0);
            let (aa, bb, cc, dd, ee) = (t, a, b.rotate_left(30), c, d);
            a = aa; b = bb; c = cc; d = dd; e = ee;
            i += 1;
        }
        while i < 40 {
            let tmp = w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf];
            w[i&0xf] = tmp<<1 | tmp>>(32-1);
            let f = b ^ c ^ d;
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(w[i&0xf]).wrapping_add(K1);
            let (aa, bb, cc, dd, ee) = (t, a, b.rotate_left(30), c, d);
            a = aa; b = bb; c = cc; d = dd; e = ee;
            i += 1;
        }
        while i < 60 {
            let tmp = w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf];
            w[i&0xf] = tmp<<1 | tmp>>(32-1);
            let f = ((b | c) & d) | (b & c);
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(w[i&0xf]).wrapping_add(K2);
            let (aa, bb, cc, dd, ee) = (t, a, b.rotate_left(30), c, d);
            a = aa; b = bb; c = cc; d = dd; e = ee;
            i += 1;
        }
        while i < 80 {
            let tmp = w[(i-3)&0xf] ^ w[(i-8)&0xf] ^ w[(i-14)&0xf] ^ w[(i)&0xf];
            w[i&0xf] = tmp<<1 | tmp>>(32-1);
            let f = b ^ c ^ d;
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(w[i&0xf]).wrapping_add(K3);
            let (aa, bb, cc, dd, ee) = (t, a, b.rotate_left(30), c, d);
            a = aa; b = bb; c = cc; d = dd; e = ee;
            i += 1;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);

        p = &p[64..];
    }

    let mut sum = [0u8; 20];
    putbigu32(&mut sum[0..], h0);
    putbigu32(&mut sum[4..], h1);
    putbigu32(&mut sum[8..], h2);
    putbigu32(&mut sum[12..], h3);
    putbigu32(&mut sum[16..], h4);
    sum
}

fn putbigu64(b : &mut [u8], v : u64) {
    b[0] = (v >> 56) as u8;
    b[1] = (v >> 48) as u8;
    b[2] = (v >> 40) as u8;
    b[3] = (v >> 32) as u8;
    b[4] = (v >> 24) as u8;
    b[5] = (v >> 16) as u8;
    b[6] = (v >> 8) as u8;
    b[7] = v as u8;
}

fn putbigu32(b : &mut [u8], v : u32) {
    b[0] = (v >> 24) as u8;
    b[1] = (v >> 16) as u8;
    b[2] = (v >> 8) as u8;
    b[3] = v as u8;
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[test]
    fn test_sha1() {
        assert_eq!(super::sha1(b"hello"), [0xaa, 0xf4, 0xc6, 0x1d, 0xdc, 0xc5, 0xe8, 0xa2, 0xda, 0xbe, 0xde, 0xf, 0x3b, 0x48, 0x2c, 0xd9, 0xae, 0xa9, 0x43, 0x4d]);

    }
}
