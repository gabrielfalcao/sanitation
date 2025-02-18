//! SString (portmanteau of "Sanitation String") is a struct providing
//! methods to take streams of bytes and produce a UTF-8 [`String`],
//! storing invalid UTF-8 byte-sequences and associated metadata for
//! later analysis.
//!
//! SString is designed to be a generally safer and smarter
//! alternative to both [`String::from_utf8`] and
//! [`String::from_utf8_unchecked`] not only because one valid
//! [`String`] is safely produced, also because all non-valid UTF-8
//! bytes are stored within SString's internal state for forensic
//! analysis, debugging, error reporting etc.
//!
//! The entire Sanitation and, consequently, `SString` was primarily
//! intended for empowering programs and developers implementing
//! binary protocols and came to fruition while its author, [Gabriel
//! Falcão](https://github.com/gabrielfalcao), read the "The Secure
//! Shell (SSH) Protocol Architecture" specification - i.e.: [RFC
//! 4251](https://datatracker.ietf.org/doc/html/rfc4251) - and noticed
//! that document's ["Section
//! 5"](https://datatracker.ietf.org/doc/html/rfc4251#section-5) does
//! not appear to disallow the application of all non-zero values
//! beyond one on some occasions and therefore might unwarrantedly
//! leave open several hidden communication channels throughout SSH
//! networks.
//!
//! In conclusion the entire `sanitation` crate for was devised
//! because such fact appear to offer opportunities for both
//! exploiting and protecting covert communication channels within
//! such not uncommonly used network protocol.
//!
//! Putting it simply, SString serves as an effective tool to convert
//! streams of bytes into valid strings while providing ways to check
//! whether seeming garbage bytes might actually characterize exploits
//! or covert communication channels, empowering developers and programs, for
//! instance, to kill unwanted connections, insecure connections or
//! even poorly-secured connections.
//!
//! Perhaps more succinctly said, SStrings allow analysing potential
//! bugs from remote connections, detecting and avoiding common issues
//! such as attempted buffer-overflow attacks.
//!
//! #### Usage Example
//!
//! ```
//! use sanitation::SString;
//! // Example from https://www.exploit-db.com/exploits/51310
//! let hospital_run = vec![
//!     0x63, 0x6F, 0x6E, 0x73, 0x74, 0x20, 0x72, 0x65, 0x6E, 0x64, 0x65, 0x72, 0x50, 0x72,
//!     0x6F, 0x63, 0x65, 0x73, 0x73, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E, 0x63,
//!     0x65, 0x73, 0x20, 0x3D, 0x20, 0x70, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x2E, 0x61,
//!     0x74, 0x6F, 0x6D, 0x42, 0x69, 0x6E, 0x64, 0x69, 0x6E, 0x67, 0x28, 0x27, 0x72, 0x65,
//!     0x6E, 0x64, 0x65, 0x72, 0x5F, 0x70, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x5F, 0x70,
//!     0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E, 0x63, 0x65, 0x73, 0x27, 0x29, 0x2E, 0x66,
//!     0x6F, 0x72, 0x41, 0x6C, 0x6C, 0x57, 0x65, 0x62, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E,
//!     0x74, 0x73, 0x28, 0x29,
//! ];
//! let hr = SString::new(&hospital_run);
//!
//! assert_eq!(hr.garbage(), vec![]);
//! assert_eq!(&hr.unchecked_safe(), "const renderProcessPreferences = process.atomBinding('render_process_preferences').forAllWebContents()");
//! ```

use crate::errors::Error;
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Read;
use std::str::{from_utf8, Utf8Error};
/// `SString` is a struct which keeps an internal state comprised of data fed into it:
///
/// - A [`Vec`] of sequential bytes
/// - All valid UTF-8 bytes
/// - All invalid UTF-8 bytes available for analysis
/// - A list of 2-item tuples with the start and ends of each chunk of valid UTF-8 found by [`SString::extend_vec`]
#[derive(Clone)]
pub struct SString {
    g: Vec<u8>,
    p: Vec<(usize, usize)>,
    i: Vec<u8>,
    s: Vec<u8>,
}
impl SString {
    /// Creates new instance of [`SString`] from implementations of [`std::io::Read`] and [`std::fmt::Debug`]
    pub fn from_io_read(mut s: impl Read + ::std::fmt::Debug) -> ::std::io::Result<SString> {
        let mut raw: Vec<u8> = Vec::new();
        s.read(&mut raw)?;
        Ok(SString::new(&raw))
    }

    /// Creates new instance of [`SString`] from stream of bytes
    pub fn new(raw: &[u8]) -> SString {
        let mut sstring = SString::empty();
        sstring.extend_vec(raw.to_vec(), |_, error| Err(error));
        sstring
    }

    /// Creates new empty instance of [`SString`]
    pub fn empty() -> SString {
        SString {
            g: Vec::new(),
            p: Vec::<(usize, usize)>::new(),
            i: Vec::new(),
            s: Vec::new(),
        }
    }

    /// `SString::extend_vec` is the principal method of [`SString`]. It takes all valid UTF-8 data from a `Vec<u8>`. It passes invalid remaining UTF-8 data to the `on_utf8_error` closure whose responsibility is to either transform the invalid bytes into a valid String or return [`Utf8Error`].
    pub fn extend_vec(&mut self, raw: Vec<u8>, mut on_utf8_error: impl OnUtf8Error) {
        let mut input = raw.clone();
        self.i.extend(&input);
        loop {
            match from_utf8(&input) {
                Ok(valid) => {
                    self.s.extend(valid.as_bytes());
                    break;
                }
                Err(error) => match on_utf8_error(input.clone(), error) {
                    Ok(valid) => {
                        self.s.extend(valid.as_bytes());
                        break;
                    }
                    Err(error) => {
                        let (valid, after_valid) = input.split_at(error.valid_up_to());
                        self.s.extend(valid);

                        if let Some(error_len) = error.error_len() {
                            let valid_start = error.valid_up_to();
                            let valid_end = valid_start + error_len;

                            self.p.insert(0, (valid_start, valid_end));
                            let bytes = &mut input[valid_start..valid_end].to_vec();
                            self.g.extend(&mut bytes.iter());
                            input = after_valid[error_len..].to_vec();
                        } else {
                            break;
                        }
                    }
                },
            }
        }
    }

    /// `SString::append` processes a single [`u8`] checking whether is a valid UTF-8 and adding it to the
    /// internal state of the SString instance from which this method is called.
    /// This method takes a [`OnUtf8Error`] callback, not unlike the [`SString::extend_vec`] method.
    pub fn append(&mut self, byte: u8, on_utf8_error: impl OnUtf8Error) {
        self.extend_vec(vec![byte], on_utf8_error)
    }

    /// `SString::push` processes a single [`u8`] checking whether is a valid UTF-8 and adding it to the internal state of the SString instance from which this method is called.
    pub fn push(&mut self, byte: u8) {
        self.append(byte, |_, w| Err(w))
    }

    /// `SString::safe` returns a valid string under the condition
    /// that no invalid UTF-8 bytes were fed into SString at all. If
    /// there are one or more non-valid UTF-8 bytes within the calling
    /// SString this method returns a [`Error`].
    ///
    /// The method [`SString::unchecked_safe`] might be suitable on
    /// occasions where one resolves to produce a string comprised of
    /// all contiguous valid UTF-8 bytes fed into a SString's
    /// instance.
    pub fn safe(&self) -> Result<String, Error> {
        match String::from_utf8(self.i.clone()) {
            Ok(string) => Ok(string),
            Err(e) => {
                if self.has_garbage() {
                    Err(crate::Error::UnsafeString(&self.s, &self.g))
                } else {
                    Err(crate::Error::InvalidUtf8(
                        e, &self.g, &self.p, &self.i, &self.s,
                    ))
                }
            }
        }
    }

    /// `SString::unchecked_safe` returns a valid string comprised of
    /// all contiguous valid UTF-8 bytes fed into an instance of
    /// SString.
    pub fn unchecked_safe(&self) -> String {
        String::from_utf8(self.s.clone()).expect("valid UTF-8 bytes")
    }

    /// `SString::garbage_len` returns the length of the contiguous
    /// non-valid UTF-8 bytes within its associated SString instance.
    pub fn garbage_len(&self) -> usize {
        self.g.len()
    }

    /// `SString::garbage` returns a [`Vec<u8>`] with all the
    /// contiguous non-valid UTF-8 bytes fed into its associated
    /// SString.
    ///
    /// This method might be perceived as having an opposing function
    /// to that of the [`SString::safe_vec`] method.
    pub fn garbage(&self) -> Vec<u8> {
        self.g.clone()
    }

    /// `SString::has_garbage` returns [`true`] if there is one or
    /// more non-valid UTF-8 bytes within its associated SString
    /// instance.
    pub fn has_garbage(&self) -> bool {
        self.garbage_len() > 0
    }

    /// `SString::safe_len` returns the length of the contiguous
    /// non-valid UTF-8 bytes within its associated SString instance.
    pub fn safe_len(&self) -> usize {
        self.s.len()
    }

    /// `SString::safe_vec` returns a [`Vec<u8>`] with all the
    /// contiguous valid UTF-8 bytes fed into its associated
    /// SString.
    ///
    /// This method might be perceived as having an opposing function
    /// to that of the [`SString::garbage`] method.
    pub fn safe_vec(&self) -> Vec<u8> {
        self.s.clone()
    }

    /// `SString::len` returns the length of all bytes fed into its
    /// associated SString making non-discriminating whether safe or unsafe.
    pub fn len(&self) -> usize {
        self.i.len()
    }

    /// `SString::tocow` returns a [`Cow<'static, str>`] comprised of
    /// all contiguous valid UTF-8 bytes fed into an instance of
    /// SString.
    pub fn tocow(&self) -> Cow<'static, str> {
        Cow::Owned(self.unchecked_safe())
    }

    /// `SString::toosstr` returns a [`OsString`] comprised of all
    /// contiguous valid UTF-8 bytes fed into an instance of SString.
    pub fn toosstr(&self) -> OsString {
        let mut osstr = OsString::new();
        osstr.push(self.unchecked_safe());
        osstr
    }

    /// `SString::valid_utf8_chunk_boundaries` returns a [`Vec<(usize, usize)>`] comprised of all
    /// the `(start, end)` boundaries of valid UTF-8 chunks of bytes
    pub fn valid_utf8_chunk_boundaries(&self) -> Vec<(usize, usize)> {
        self.p.clone()
    }
}

impl Into<Cow<'static, str>> for SString {
    fn into(self) -> Cow<'static, str> {
        self.tocow()
    }
}

impl<'s> Into<&'s str> for SString {
    fn into(self) -> &'s str {
        self.unchecked_safe().leak()
    }
}

impl Into<OsString> for SString {
    fn into(self) -> OsString {
        self.toosstr()
    }
}

impl From<Vec<u8>> for SString {
    fn from(p: Vec<u8>) -> SString {
        SString::new(&p)
    }
}

impl From<Cow<'static, str>> for SString {
    fn from(cow: Cow<'static, str>) -> SString {
        match cow {
            Cow::Borrowed(p) => SString::new(Into::<String>::into(p).as_bytes()),
            Cow::Owned(o) => SString::new(o.as_bytes()),
        }
    }
}

impl From<OsString> for SString {
    fn from(os: OsString) -> SString {
        SString::new(&os.into_encoded_bytes())
    }
}

impl From<String> for SString {
    fn from(p: String) -> SString {
        SString::new(p.as_bytes())
    }
}
impl From<&str> for SString {
    fn from(p: &str) -> SString {
        SString::new(p.as_bytes())
    }
}
impl From<&OsStr> for SString {
    fn from(p: &OsStr) -> SString {
        SString::new(p.as_encoded_bytes())
    }
}

impl From<&[u8]> for SString {
    fn from(p: &[u8]) -> SString {
        SString::new(p)
    }
}

impl fmt::Display for SString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.unchecked_safe())
    }
}
impl<'a> Extend<&'a u8> for SString {
    fn extend<C: IntoIterator<Item = &'a u8>>(&mut self, iter: C) {
        for byte in iter {
            self.push(byte.clone())
        }
    }
}

impl Extend<u8> for SString {
    fn extend<C: IntoIterator<Item = u8>>(&mut self, iter: C) {
        for byte in iter {
            self.push(byte);
        }
    }
}

impl<'a> FromIterator<&'a String> for SString {
    fn from_iter<C: IntoIterator<Item = &'a String>>(strings: C) -> Self {
        let mut sstring = SString::empty();
        for string in strings {
            let bytes = string.as_bytes().to_vec();
            sstring.extend(bytes.iter());
        }
        sstring
    }
}

impl<'a> FromIterator<&'a Vec<u8>> for SString {
    fn from_iter<C: IntoIterator<Item = &'a Vec<u8>>>(vecs: C) -> Self {
        let mut sstring = SString::empty();
        for bytes in vecs {
            sstring.extend(bytes.into_iter())
        }
        sstring
    }
}

impl FromIterator<String> for SString {
    fn from_iter<C: IntoIterator<Item = String>>(strings: C) -> Self {
        let mut sstring = SString::empty();
        for string in strings {
            let bytes = string.as_bytes();
            sstring.extend(bytes.iter());
        }
        sstring
    }
}

impl FromIterator<Vec<u8>> for SString {
    fn from_iter<C: IntoIterator<Item = Vec<u8>>>(vecs: C) -> Self {
        let mut sstring = SString::empty();
        for bytes in vecs {
            sstring.extend(bytes.iter())
        }
        sstring
    }
}

impl<'a> FromIterator<&'a u8> for SString {
    fn from_iter<C: IntoIterator<Item = &'a u8>>(bytes: C) -> Self {
        let bytes = bytes
            .into_iter()
            .map(|byte| byte.clone())
            .collect::<Vec<u8>>();
        SString::new(&bytes)
    }
}

impl FromIterator<u8> for SString {
    fn from_iter<C: IntoIterator<Item = u8>>(bytes: C) -> Self {
        let bytes = bytes.into_iter().collect::<Vec<u8>>();
        SString::new(&bytes)
    }
}

impl<'a> Extend<&'a Vec<u8>> for SString {
    fn extend<C: IntoIterator<Item = &'a Vec<u8>>>(&mut self, vecs: C) {
        for bytes in vecs {
            self.extend(bytes.iter())
        }
    }
}

impl Default for SString {
    fn default() -> SString {
        SString::empty()
    }
}

/// `OnUtf8Error` is a function callback whose purpose is to take a string of non-valid UTF-8 bytes and return either a valid [`String`] or an [`Utf8Error`]
pub trait OnUtf8Error = FnMut(Vec<u8>, Utf8Error) -> Result<String, Utf8Error>;

#[cfg(test)]
mod sstring_tests {
    use crate::{Error, SString};

    #[test]
    pub fn test_sstring_from_invalid_utf8() {
        let invalid_utf8_bytes: Vec<u8> = vec![
            0xFF, 0x72, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x31, 0x47, 0x31,
        ];

        assert_eq!(
            String::from_utf8_lossy(&invalid_utf8_bytes),
            format!("�r������1G1")
        );
        let sanitation_string = SString::new(&invalid_utf8_bytes);
        let safe_vec = sanitation_string.safe_vec();
        assert_eq!(safe_vec, vec![0x72, 0x31, 0x47, 0x31]);
        let safe_string = sanitation_string.unchecked_safe();
        assert_eq!(safe_string, format!("r1G1"));
        let garbage = sanitation_string.garbage();
        assert_eq!(garbage, vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]);
    }

    #[test]
    pub fn test_capture_hospital_run_exploit() {
        // Example from https://www.exploit-db.com/exploits/51310
        let hospital_run = vec![
            0x63, 0x6F, 0x6E, 0x73, 0x74, 0x20, 0x72, 0x65, 0x6E, 0x64, 0x65, 0x72, 0x50, 0x72,
            0x6F, 0x63, 0x65, 0x73, 0x73, 0x50, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E, 0x63,
            0x65, 0x73, 0x20, 0x3D, 0x20, 0x70, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x2E, 0x61,
            0x74, 0x6F, 0x6D, 0x42, 0x69, 0x6E, 0x64, 0x69, 0x6E, 0x67, 0x28, 0x27, 0x72, 0x65,
            0x6E, 0x64, 0x65, 0x72, 0x5F, 0x70, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x5F, 0x70,
            0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E, 0x63, 0x65, 0x73, 0x27, 0x29, 0x2E, 0x66,
            0x6F, 0x72, 0x41, 0x6C, 0x6C, 0x57, 0x65, 0x62, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E,
            0x74, 0x73, 0x28, 0x29,
        ];
        let hr = SString::new(&hospital_run);

        assert_eq!(hr.garbage(), vec![]);
        assert_eq!(&hr.unchecked_safe(), "const renderProcessPreferences = process.atomBinding('render_process_preferences').forAllWebContents()");
    }

    #[test]
    pub fn test_capture_maxiguvenlik_general_device_manager() {
        // Example from https://www.exploit-db.com/exploits/51641
        let general_device_manager = vec![
            0xB8, 0x9C, 0x78, 0x14, 0x60, 0xD9, 0xC2, 0xD9, 0x74, 0x24, 0xF4, 0x5A, 0x33, 0xC9,
            0xB1, 0x31, 0x83, 0xEA, 0xFC, 0x31, 0x42, 0x0F, 0x03, 0x42, 0x93, 0x9A, 0xE1, 0x9C,
            0x43, 0xD8, 0x0A, 0x5D, 0x93, 0xBD, 0x83, 0xB8, 0xA2, 0xFD, 0xF0, 0xC9, 0x94, 0xCD,
            0x73, 0x9F, 0x18, 0xA5, 0xD6, 0x34, 0xAB, 0xCB, 0xFE, 0x3B, 0x1C, 0x61, 0xD9, 0x72,
            0x9D, 0xDA, 0x19, 0x14, 0x1D, 0x21, 0x4E, 0xF6, 0x1C, 0xEA, 0x83, 0xF7, 0x59, 0x17,
            0x69, 0xA5, 0x32, 0x53, 0xDC, 0x5A, 0x37, 0x29, 0xDD, 0xD1, 0x0B, 0xBF, 0x65, 0x05,
            0xDB, 0xBE, 0x44, 0x98, 0x50, 0x99, 0x46, 0x1A, 0xB5, 0x91, 0xCE, 0x04, 0xDA, 0x9C,
            0x99, 0xBF, 0x28, 0x6A, 0x18, 0x16, 0x61, 0x93, 0xB7, 0x57, 0x4E, 0x66, 0xC9, 0x90,
            0x68, 0x99, 0xBC, 0xE8, 0x8B, 0x24, 0xC7, 0x2E, 0xF6, 0xF2, 0x42, 0xB5, 0x50, 0x70,
            0xF4, 0x11, 0x61, 0x55, 0x63, 0xD1, 0x6D, 0x12, 0xE7, 0xBD, 0x71, 0xA5, 0x24, 0xB6,
            0x8D, 0x2E, 0xCB, 0x19, 0x04, 0x74, 0xE8, 0xBD, 0x4D, 0x2E, 0x91, 0xE4, 0x2B, 0x81,
            0xAE, 0xF7, 0x94, 0x7E, 0x0B, 0x73, 0x38, 0x6A, 0x26, 0xDE, 0x56, 0x6D, 0xB4, 0x64,
            0x14, 0x6D, 0xC6, 0x66, 0x08, 0x06, 0xF7, 0xED, 0xC7, 0x51, 0x08, 0x24, 0xAC, 0xAE,
            0x42, 0x65, 0x84, 0x26, 0x0B, 0xFF, 0x95, 0x2A, 0xAC, 0xD5, 0xD9, 0x52, 0x2F, 0xDC,
            0xA1, 0xA0, 0x2F, 0x95, 0xA4, 0xED, 0xF7, 0x45, 0xD4, 0x7E, 0x92, 0x69, 0x4B, 0x7E,
            0xB7, 0x09, 0x0A, 0xEC, 0x5B, 0xE0, 0xA9, 0x94, 0xFE, 0xFC,
        ];

        let gdm = SString::new(&general_device_manager);

        assert_eq!(
            gdm.garbage(),
            vec![
                184, 156, 217, 194, 217, 244, 131, 234, 252, 147, 154, 225, 156, 216, 147, 189,
                131, 184, 162, 253, 240, 205, 159, 165, 214, 171, 203, 254, 217, 157, 218, 246,
                234, 131, 247, 165, 220, 221, 209, 191, 152, 153, 181, 145, 206, 153, 191, 147,
                183, 153, 188, 232, 139, 199, 246, 242, 181, 244, 209, 231, 189, 165, 182, 141,
                203, 232, 189, 145, 228, 129, 174, 247, 148, 222, 180, 198, 247, 237, 199, 172,
                174, 132, 255, 149, 172, 213, 217, 160, 149, 164, 237, 247, 212, 146, 183, 236,
                254, 252
            ]
        );
        assert_eq!(format!("{}", gdm),   "x\u{14}`t$Z3ɱ11B\u{f}\u{3}BC\n]ɔs\u{18}4;\u{1c}ar\u{19}\u{14}\u{1d}!N\u{1c}Y\u{17}i2SZ7)\u{b}e\u{5}۾DPF\u{1a}\u{4}ڜ(j\u{18}\u{16}aWNfɐh$.BPp\u{11}aUcm\u{12}q$.\u{19}\u{4}tM.+~\u{b}s8j&Vmd\u{14}mf\u{8}\u{6}Q\u{8}$Be&\u{b}*R/ܡ/E~iK~\t\n[\u{a54}");
        assert_eq!(gdm.unchecked_safe(), "x\u{14}`t$Z3ɱ11B\u{f}\u{3}BC\n]ɔs\u{18}4;\u{1c}ar\u{19}\u{14}\u{1d}!N\u{1c}Y\u{17}i2SZ7)\u{b}e\u{5}۾DPF\u{1a}\u{4}ڜ(j\u{18}\u{16}aWNfɐh$.BPp\u{11}aUcm\u{12}q$.\u{19}\u{4}tM.+~\u{b}s8j&Vmd\u{14}mf\u{8}\u{6}Q\u{8}$Be&\u{b}*R/ܡ/E~iK~\t\n[\u{a54}");
        assert_eq!(
            gdm.safe(),
            Err(Error::UnsafeString(
                &[
                    120, 20, 96, 116, 36, 90, 51, 201, 177, 49, 49, 66, 15, 3, 66, 67, 10, 93, 201,
                    148, 115, 24, 52, 59, 28, 97, 114, 25, 20, 29, 33, 78, 28, 89, 23, 105, 50, 83,
                    90, 55, 41, 11, 101, 5, 219, 190, 68, 80, 70, 26, 4, 218, 156, 40, 106, 24, 22,
                    97, 87, 78, 102, 201, 144, 104, 36, 46, 66, 80, 112, 17, 97, 85, 99, 109, 18,
                    113, 36, 46, 25, 4, 116, 77, 46, 43, 126, 11, 115, 56, 106, 38, 86, 109, 100,
                    20, 109, 102, 8, 6, 81, 8, 36, 66, 101, 38, 11, 42, 82, 47, 220, 161, 47, 69,
                    126, 105, 75, 126, 9, 10, 91, 224, 169, 148
                ],
                &[
                    184, 156, 217, 194, 217, 244, 131, 234, 252, 147, 154, 225, 156, 216, 147, 189,
                    131, 184, 162, 253, 240, 205, 159, 165, 214, 171, 203, 254, 217, 157, 218, 246,
                    234, 131, 247, 165, 220, 221, 209, 191, 152, 153, 181, 145, 206, 153, 191, 147,
                    183, 153, 188, 232, 139, 199, 246, 242, 181, 244, 209, 231, 189, 165, 182, 141,
                    203, 232, 189, 145, 228, 129, 174, 247, 148, 222, 180, 198, 247, 237, 199, 172,
                    174, 132, 255, 149, 172, 213, 217, 160, 149, 164, 237, 247, 212, 146, 183, 236,
                    254, 252
                ]
            ))
        );
    }
    #[test]
    pub fn test_sstring_from_iterator() {
        let bytes: Vec<u8> = vec![0x7E, 0x3F, 0x7E];
        let sstring = bytes.iter().collect::<SString>();
        assert_eq!(sstring.unchecked_safe(), "~?~");

        let bytes: Vec<u8> = vec![0xFF, 0x7E, 0x3F, 0x7E, 0xFF];
        let sstring = bytes.iter().collect::<SString>();
        assert_eq!(sstring.unchecked_safe(), "~?~");

        let strings: Vec<String> = vec![format!("~"), format!("?"), format!("~")];
        let sstring = strings.iter().collect::<SString>();
        assert_eq!(sstring.unchecked_safe(), "~?~");

        let vecs: Vec<Vec<u8>> = vec![vec![0xFF, 0x7E], vec![0xF0, 0x3F, 0xF0], vec![0x7E, 0xFF]];
        let sstring = vecs.iter().collect::<SString>();
        assert_eq!(sstring.unchecked_safe(), "~?~");

        let strings: Vec<String> = vec![format!("~"), format!("?"), format!("~")];
        let sstring = strings
            .iter()
            .map(|string| string.clone())
            .collect::<SString>();
        assert_eq!(sstring.unchecked_safe(), "~?~");

        let vecs: Vec<Vec<u8>> = vec![vec![0xFF, 0x7E], vec![0xF0, 0x3F, 0xF0], vec![0x7E, 0xFF]];
        let sstring = vecs.iter().map(|bytes| bytes.clone()).collect::<SString>();
        assert_eq!(sstring.unchecked_safe(), "~?~");
    }
}
