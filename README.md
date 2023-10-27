# sanitation

data types for forensic analysis of protocol implementations et
cetera.

## Basic Design

Structs provide a `garbage()` method which returns potentially
malicious bytes, particularly useful for detecting attempts to
buffer-overflow in protocol implementations

```shell
cargo add sanitation
```

## Mini Demo

```rust
// Based on https://www.exploit-db.com/exploits/51641
use sanitation::SString;
let general_device_manager = vec![0xeb, 0x06, 0x90, 0x90, 0x14, 0xd9, 0xc6, 0xbb, 0xae, 0xc7, 0xed, 0x8e, 0xd9, 0x74, 0x24, 0xf4];
let gdm = SString::new(&general_device_manager);

assert_eq!(gdm.garbage(), vec![235, 144, 144, 217, 174, 199, 237, 142, 217]);
assert_eq!(&gdm.soft_word(), "\u{6}\u{14}ƻt$");
```
