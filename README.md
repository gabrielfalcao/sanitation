# sanitation

Tool for developing memory-safe programs while detecting and capturing possibly malicious bytes.

## Basic Design


Structs within the `sanitation` crate provide a `garbage()` method
which returns potentially malicious bytes or covert communication
channels.

Putting it simply, this crate serves as an effective tool to convert
streams of bytes into valid strings while providing ways to check
whether seeming garbage bytes might actually characterize *exploits* or
*covert communication channels*, empowering developers and programs, for
instance, to kill unwanted connections, insecure connections or even
poorly-secured connections.


```shell
cargo add sanitation
```

## Example

```rust
use sanitation::{to_hex, Error, SString};

fn main() -> Result<(), Error<'static>> {
    let data = [
        0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e,
        0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72,
        0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0xf4, 0xf1,
        0xf2, 0xf3,
    ];
    let sstring = SString::new(&data);
    println!("UTF-8 Safe String:\t{}", sstring.unchecked_safe());
    println!("Non-valid UTF-8 bytes:\t{}", to_hex(&sstring.garbage()));
    Ok(())
}
```
