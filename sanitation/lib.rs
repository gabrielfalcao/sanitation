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
