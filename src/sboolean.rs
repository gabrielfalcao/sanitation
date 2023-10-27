use std::fmt;


//       _/_/_/  _/_/_/                        _/
//    _/        _/    _/    _/_/      _/_/    _/    _/_/      _/_/_/  _/_/_/
//     _/_/    _/_/_/    _/    _/  _/    _/  _/  _/_/_/_/  _/    _/  _/    _/
//        _/  _/    _/  _/    _/  _/    _/  _/  _/        _/    _/  _/    _/
// _/_/_/    _/_/_/      _/_/      _/_/    _/    _/_/_/    _/_/_/  _/    _/
//
//
/// A boolean value is stored as a single byte.  The value 0
/// represents FALSE, and the value 1 represents TRUE.  All non-zero
/// values MUST be interpreted as TRUE; however, applications MUST NOT
/// store values other than 0 and 1.

pub struct SBoolean(u8, Option<u8>);
impl fmt::Display for SBoolean {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.value())
    }
}
impl fmt::Debug for SBoolean {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let result = write!(fmt, "ssh-boolean: {}", self.value());
        match self.garbage() {
            None => result,
            Some(t) => write!(fmt, "\r\ngarbage: 0x{}", t),
        }
    }
}

impl SBoolean {
    pub fn new(value: u8) -> SBoolean {
        SBoolean(
            value,
            match value {
                0|1 => None,
                _ => Some(value)
            },
        )
    }
    pub fn value(&self) -> bool {
        match &self.0 {
            0 => false,
            _ => true
        }
    }
    pub fn garbage(&self) -> Option<u8> {
        self.1.clone()
    }
}

#[cfg(test)]
mod sbooolean_tests {
    use super::SBoolean;

    #[test]
    pub fn test_sboolean_0_false_without_garbage() {
        let b = SBoolean::new(0x0);
        assert_eq!(b.value(), false);
        assert_eq!(b.garbage(), None);
    }

    #[test]
    pub fn test_sboolean_1_true_without_garbage() {
        let b = SBoolean::new(0x1);
        assert_eq!(b.value(), true);
        assert_eq!(b.garbage(), None);
    }

    #[test]
    pub fn test_sboolean_2_true_with_garbage() {
        let b = SBoolean::new(0x2);
        assert_eq!(b.value(), true);
        assert_eq!(b.garbage(), Some(0x2));
    }
}
