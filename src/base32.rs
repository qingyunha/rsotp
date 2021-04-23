#[allow(dead_code)]
pub fn encode(s: &str) -> Vec<u8> {
    let b32aplphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".as_bytes();
    let sp = s.as_bytes();
    let mut rv: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < s.len() * 8 {
        let si = i / 8;
        let sm = i % 8;
        let k = if 8 - sm >= 5 {
            //println!("-- {:08b}", sp[si]);
            (sp[si] >> (3 - sm)) & 0x1f
        } else {
            let nn = if si + 1 >= s.len() { 0 } else { sp[si + 1] };
            //println!("-- {:08b} {:08b}", sp[si], nn);
            ((sp[si] << (sm - 3)) + (nn >> (11 - sm))) & 0x1f
        };
        //println!("{} {} {:08b}", si, sm, k);
        i += 5;
        rv.push(b32aplphabet[k as usize]);
    }
    match s.len() % 5 {
        1 => {
            rv.extend_from_slice(&[0x3d; 6]);
        }
        2 => {
            rv.extend_from_slice(&[0x3d; 4]);
        }
        3 => {
            rv.extend_from_slice(&[0x3d; 3]);
        }
        4 => {
            rv.push(0x3d);
        }
        _ => {}
    }
    rv
}

pub fn decode(s: &str) -> Vec<u8> {
    let mut rv: Vec<u8> = vec![];
    let mut b32aplphabet = [0u8; 100];
    let mut i = 0;
    for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".bytes() {
        b32aplphabet[b as usize] = i;
        i += 1
    }
    let mut haveeq = false;
    for b in s.bytes() {
        if b == '=' as u8 {
            haveeq = true;
            break;
        }
        rv.push(b32aplphabet[b as usize]);
    }
    let mut si = 0;
    let mut sm = 0;
    let mut rrv = Vec::with_capacity(rv.len());
    rrv.resize(rv.len(), 0);
    for b in rv {
        let need = 8 - sm;
        if need >= 5 {
            rrv[si] = rrv[si] | (b << (3 - sm));
            sm += 5;
        } else {
            rrv[si + 1] = b << (8 - (5 - need));
            rrv[si] = rrv[si] | (b >> (5 - need));
            sm = 5 - need;
            si += 1;
        }
    }
    if haveeq {
        si -= 1
    }
    rrv.truncate(si + 1);
    rrv
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_base32() {
        assert_eq!(crate::base32::encode("hello"), "NBSWY3DP".as_bytes());
        assert_eq!(crate::base32::encode("hell"), "NBSWY3A=".as_bytes());
        assert_eq!(crate::base32::encode("hel"), "NBSWY===".as_bytes());

        assert_eq!(crate::base32::decode("NBSWY==="), "hel".as_bytes());
        assert_eq!(crate::base32::decode("NBSWY3DP"), "hello".as_bytes());
    }
}
