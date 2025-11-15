//! sanitation is a tool for developing memory-safe programs while
//! detecting and capturing possibly malicious bytes.

pub mod errors;
pub mod sboolean;
pub mod sstring;
pub mod traits;

pub use errors::*;
pub use sboolean::*;
pub use sstring::*;
pub use traits::*;

/// Converts array of bytes into hexadecimal [`String`] representation.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut to_hex = String::new();
    for byte in bytes {
        to_hex.extend(format!("{:02x}", byte).chars());
    }
    format!("0x{}", to_hex)
}

#[test]
fn test_to_hex() {
    let bytes = vec![0xF0, 0x53, 0x75, 0x52, 0x65];
    assert_eq!(to_hex(&bytes), "0xf053755265");
}

pub fn from_hex(hex: &str) -> Result<Vec<u8>, crate::Error> {
    if hex.is_empty() {
        return Err(crate::Error::ParseError(
            "empty hexadecimal string".to_string(),
        ));
    }
    let hex = hex.to_lowercase();
    let hex = if hex.starts_with("0x") {
        hex[2..].to_string()
    } else if hex.starts_with("x") {
        hex[1..].to_string()
    } else {
        hex.to_string()
    };
    for (j, c) in hex.chars().enumerate() {
        match c {
            'a' | 'b' | 'c' | 'd' | 'e' | 'f' | '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7'
            | '8' | '9' => {}
            _ => {
                return Err(Error::ParseError(format!(
                    "invalid hexadecimal character at pos {}: {}",
                    j + 1,
                    c
                )))
            }
        }
    }
    let hex = if hex.len() % 2 != 0 {
        format!("0{}", hex)
    } else {
        hex
    };

    let mut bytes = Vec::<u8>::new();
    let mut next = 2;
    while next <= hex.len() {
        bytes.push(u8::from_str_radix(&hex[next - 2..next], 16)?);
        next += 2;
    }
    Ok(bytes)
}

#[test]
fn test_from_hex() -> Result<(), crate::Error<'static>> {
    assert_eq!(from_hex("0x0")?, vec![0u8]);
    assert_eq!(
        from_hex("0xffffffffffffffff")?,
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    assert_eq!(
        from_hex("0x0")?,
        vec![0x0],
    );
    assert_eq!(
        from_hex("0xf")?,
        vec![0x0f],
    );
    assert_eq!(
        from_hex("0x0f")?,
        vec![0x0f],
    );
    assert_eq!(
        from_hex("0xeff")?,
        vec![0x0e, 0xff],
    );
    assert_eq!(
        from_hex("0xffffffffffffffff")?,
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );

    Ok(())
}
