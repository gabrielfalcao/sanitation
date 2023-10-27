use std::fmt;
use std::str::from_utf8;

//       _/_/_/    _/_/_/    _/                _/
//    _/        _/        _/_/_/_/  _/  _/_/      _/_/_/      _/_/_/
//     _/_/      _/_/      _/      _/_/      _/  _/    _/  _/    _/
//        _/        _/    _/      _/        _/  _/    _/  _/    _/
// _/_/_/    _/_/_/        _/_/  _/        _/  _/    _/    _/_/_/
//                                                          _/
//                                                       _/_/

/// SString (Sanitation String) is, in a nutshell, a string from a
/// UTF-8 byte-sequence with garbage collection for later
/// analysis. SString is intended for use in binary-protocol
/// implementations (e.g.: RFC-4251
/// <https://datatracker.ietf.org/doc/html/rfc4251#section-5>) or
/// other occasions where the definition of `string` as appears as
/// some kind or sort of binary string expecting valid UTF-8.

/// In other words SString is a data-structure acting as a
/// dual-data-channel where the garbage can be analysed for capturing
/// bugs in connections, revealing bugs in remote connections and
/// generally detecting problems e.g.: buffer-overflow attacks.

//
#[derive(Clone)]
pub struct SString(Vec<u8>, Option<Vec<u8>>);

impl fmt::Display for SString {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.soft_word())
    }
}
impl fmt::Debug for SString {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let gbg = self.garbage();
        write!(fmt, "sanitation-string: {}", self.soft_word())?;
        write!(fmt, "\r\ngarbage: 0x{}", gbg.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().join(""))
    }
}

impl SString {
    pub fn new(input: &[u8]) -> SString {
        let mut input = input.to_vec();
        let mut string: Vec<u8> = Vec::new();
        let mut garbage: Vec<u8> = Vec::new();
        loop {
            match from_utf8(&input) {
                Ok(valid) => {
                    string.extend(valid.as_bytes());
                    break;
                }
                Err(error) => {
                    let (valid, after_valid) = input.split_at(error.valid_up_to());
                    string.extend(valid);

                    if let Some(il) = error.error_len() {
                        let is = error.valid_up_to();
                        let ie = is + il;
                        let byte = &input[is..ie];
                        garbage.extend(byte);
                        input = after_valid[il..].to_vec();
                    } else {
                        break;
                    }
                }
            }
        }
        SString(
            string,
            if garbage.len() > 0 {
                Some(garbage)
            } else {
                None
            },
        )
    }
    pub fn soft_word(&self) -> String {
        String::from_utf8(self.0.clone()).expect("garbage to evidently possess some data")
    }
    pub fn soft_string(&self) -> Vec<u8> {
        self.0.clone()
    }
    pub fn garbage(&self) -> Vec<u8> {
        match &self.1 {
            None => Vec::new(),
            Some(v) => v.clone(),
        }
    }
}


#[cfg(test)]
mod sstring_tests {
    use super::SString;

    #[test]
    pub fn test_sstring_from_invalid_utf8() {
        let invalid_utf8_bytes: Vec<u8> = vec![
            0xff, 0x72, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x31, 0x47, 0x31,
        ];

        assert_eq!(
            String::from_utf8_lossy(&invalid_utf8_bytes),
            format!("�r������1G1")
        );
        let ssh_string = SString::new(&invalid_utf8_bytes);
        let ss = ssh_string.soft_string();
        assert_eq!(ss, vec![0x72, 0x31, 0x47, 0x31]);
        let sw = ssh_string.soft_word();
        assert_eq!(sw, format!("r1G1"));
        let gbg = ssh_string.garbage();
        assert_eq!(gbg, vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]);
    }
}
