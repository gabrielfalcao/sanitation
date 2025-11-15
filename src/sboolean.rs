//! SBoolean (portmanteau of "Sanitation Boolean") is a struct
//! providing methods to accept exactly one [`u8`] byte and produce a
//! [`bool`] equivalent.  As one might expect, [`SBoolean`] represents
//! `0u8` as [`false`] and `1u8` as [`true`]. But more importantly,
//! all other [`u8`] values are accepted as [`true`] under the
//! condition of being flagged and stored as potentially malicious,
//! unsafe or a possible covert communication channel.
//!

use std::fmt;

/// `SBoolean` stores as a single [`u8`]. The value 0 represents
/// [`false`], and the value 1 represents [`true`].  All non-zero
/// values are interpreted as [`true`] but are also flagged and stored
/// as garbage.
pub struct SBoolean {
    value: u8,
}
impl SBoolean {
    pub fn new(value: u8) -> SBoolean {
        SBoolean { value }
    }
    pub fn value(&self) -> bool {
        match self.value {
            0 => false,
            _ => true,
        }
    }
    pub fn garbage(&self) -> Option<u8> {
        match self.value {
            0|1 => None,
            garbage => Some(garbage),
        }
    }
}

impl fmt::Display for SBoolean {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.value())
    }
}

impl fmt::Debug for SBoolean {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let result = write!(fmt, "sanitation-boolean: {}", self.value());
        match self.garbage() {
            None => result,
            Some(t) => write!(fmt, "\r\ngarbage: 0x{}", t),
        }
    }
}


#[cfg(test)]
mod sbooolean_tests {
    use super::SBoolean;

    #[test]
    pub fn test_sboolean_false_without_garbage() {
        let b = SBoolean::new(0x0);
        assert_eq!(b.value(), false);
        assert_eq!(b.garbage(), None);
    }

    #[test]
    pub fn test_sboolean_true_without_garbage() {
        let b = SBoolean::new(0x1);
        assert_eq!(b.value(), true);
        assert_eq!(b.garbage(), None);
    }

    #[test]
    pub fn test_sboolean_true_with_garbage() {
        let b = SBoolean::new(0x2);
        assert_eq!(b.value(), true);
        assert_eq!(b.garbage(), Some(0x2));

        let b = SBoolean::new(0xf4);
        assert_eq!(b.value(), true);
        assert_eq!(b.garbage(), Some(0xf4));
    }
}
