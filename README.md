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
