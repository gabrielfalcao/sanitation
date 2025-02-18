//! the traits module contains the [`SafeString`].
use crate::sstring::SString;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::ffi::OsString;

/// The `SafeString` trait is useful for converting from various string-related types into [`SString`].
pub trait SafeString: Into<SString> + Clone {
    fn as_str(self) -> &'static str {
        Into::<SString>::into(self).unchecked_safe().leak()
    }
    fn into_bytes(&self) -> Vec<u8> {
        self.clone().as_str().as_bytes().to_vec()
    }
}

impl SafeString for SString {
    fn as_str(self) -> &'static str {
        self.unchecked_safe().leak()
    }
}

impl SafeString for String {}

impl SafeString for OsString {}

impl<'a> SafeString for &'a str {}
impl<'a> SafeString for &'a OsStr {}

impl SafeString for Cow<'static, str> {}
