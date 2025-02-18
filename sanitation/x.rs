
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
