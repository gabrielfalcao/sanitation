//! `errors` module contains the [`Error`] struct which is used across the `sanitation` crate to simplify error handling by transforming specific errors from known crates into [`Error`].



use crate::to_hex;
use ::std::string::FromUtf8Error;

/// `Error` represents errors occurring within the `sanitation` crate.
#[derive(Debug, Clone, PartialEq)]
pub enum Error<'a> {
    UnsafeString(&'a [u8], &'a [u8]),
    InvalidUtf8(FromUtf8Error, &'a [u8], &'a [(usize, usize)], &'a [u8], &'a [u8]),
}

impl std::fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::UnsafeString(s, h) => write!(f, "unsafe conversion of byte-sequence {:#?} to string: contains garbage {:#?}", to_hex(s), to_hex(h)),
            Error::InvalidUtf8(e, g, p, _r_, _s_) => {
                let facets = p.iter().map(|(b, e)| format!("{}-{}", b, e)).collect::<Vec<String>>().join(", ");
                write!(f, "unsafe byte array conversion to string `{}': {} at locations {{{}}}", e, facets, to_hex(g))
            },
        }
    }
}

impl std::error::Error for Error<'_> {}
impl Into<std::io::Error> for Error<'_> {
    fn into(self) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}", self))
    }
}
