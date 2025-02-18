use sanitation::{to_hex, Error, SString};

fn main() -> Result<(), Error<'static>> {
    let mut data = vec![
        0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e,
        0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72,
        0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0xf4, 0xf1, 0xf3
    ];
    let sstring_with_garbage = SString::new(&data);
    match SString::new(&data).safe() {
        Ok(data) => panic!("{} should not reach here", data),
        Err(e) => eprintln!("Error: {}", e),
    }
    println!("Non-valid UTF-8 bytes:\t{}", to_hex(&sstring_with_garbage.garbage()));
    println!("Starts/Ends of valid UTF-8 chunks:\t{:#?}", sstring_with_garbage.valid_utf8_chunk_boundaries());

    data.remove(45);
    data.remove(44);
    let sstring = SString::new(&data);
    println!("UTF-8 Safe String:\t{}", sstring.unchecked_safe());
    Ok(())
}
