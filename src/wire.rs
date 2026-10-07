// SPDX-License-Identifier: MIT OR Apache-2.0

//! The marshalling primitives every structure is built from.
//!
//! Everything a guest sends is read through a [`Reader`], whose every read is bounds-checked and
//! fails as `TPM_RC_INSUFFICIENT`. A `TPM2B` is read once, as a [`Bytes`] that carries its bound in
//! its type, and is a slice from then on: its size and its buffer never travel apart.

use crate::rc::{At, Fmt1, Rc};

/// A cursor over guest bytes.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Fmt1> {
        if n > self.buf.len() {
            return Err(Fmt1::Insufficient);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Fmt1> {
        let b = self.bytes(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8, Fmt1> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u16(&mut self) -> Result<u16, Fmt1> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, Fmt1> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// The next `n` bytes as a reader of their own, for an area whose size the wire states.
    pub fn split(&mut self, n: usize) -> Result<Reader<'a>, Fmt1> {
        Ok(Reader::new(self.bytes(n)?))
    }

    /// A `TPM2B` of at most `MAX` bytes. A larger size is `TPM_RC_SIZE`, as Part 2 requires,
    /// before any of the buffer is read.
    pub fn tpm2b<const MAX: usize>(&mut self) -> Result<Bytes<'a, MAX>, Fmt1> {
        let n = usize::from(self.u16()?);
        if n > MAX {
            return Err(Fmt1::Size);
        }
        Ok(Bytes(self.bytes(n)?))
    }

    /// Everything left, which must be nothing: a command with bytes after its last parameter
    /// is `TPM_RC_SIZE`.
    pub fn finish(self) -> Result<(), Fmt1> {
        if self.buf.is_empty() { Ok(()) } else { Err(Fmt1::Size) }
    }
}

/// A `TPM2B` buffer read from the wire: at most `MAX` bytes, by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bytes<'a, const MAX: usize>(&'a [u8]);

impl<'a, const MAX: usize> Bytes<'a, MAX> {
    pub fn get(self) -> &'a [u8] {
        self.0
    }
}

/// An owned buffer of at most `MAX` bytes. Only a [`Bytes`] of the same bound or a fixed array
/// that fits can make one, so the bound never has to be checked again.
#[derive(Clone)]
pub struct Buf<const MAX: usize> {
    len: usize,
    data: [u8; MAX],
}

impl<const MAX: usize> Buf<MAX> {
    pub const fn empty() -> Self {
        Buf { len: 0, data: [0; MAX] }
    }

    pub fn from_wire(b: Bytes<'_, MAX>) -> Self {
        let mut buf = Self::empty();
        buf.data[..b.0.len()].copy_from_slice(b.0);
        buf.len = b.0.len();
        buf
    }

    #[cfg(test)]
    pub fn from_array<const N: usize>(a: [u8; N]) -> Self {
        const { assert!(N <= MAX) };
        let mut buf = Self::empty();
        buf.data[..N].copy_from_slice(&a);
        buf.len = N;
        buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Drops trailing zero bytes, as the TPM does to every authValue it stores or compares.
    pub fn trim_trailing_zeros(&mut self) {
        while self.len > 0 && self.data[self.len - 1] == 0 {
            self.len -= 1;
        }
    }
}

impl<const MAX: usize> zeroize::Zeroize for Buf<MAX> {
    fn zeroize(&mut self) {
        self.data.zeroize();
        self.len = 0;
    }
}

/// Response bytes being built.
#[derive(Default, Debug)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer::default()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    /// A `TPM2B`. What the engine writes is its own data, so a buffer too large for the size
    /// field is an engine bug, not guest input.
    pub fn tpm2b(&mut self, b: &[u8]) {
        let n = u16::try_from(b.len()).expect("a TPM2B the engine built exceeds 64 KiB");
        self.u16(n);
        self.bytes(b);
    }

    /// Overwrites four bytes already written, for a size field known only afterwards.
    pub fn patch_u32(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_be_bytes());
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

/// Attaches a position to an unmarshalling fault.
pub trait Blame<T> {
    fn at(self, at: At) -> Result<T, Rc>;
}

impl<T> Blame<T> for Result<T, Fmt1> {
    fn at(self, at: At) -> Result<T, Rc> {
        self.map_err(|e| Rc::Fmt1(e, Some(at)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tpm2b_larger_than_its_bound_is_size_before_it_is_insufficient() {
        // Claims 40 bytes, carries 2: the bound is checked first.
        let mut r = Reader::new(&[0, 40, 1, 2]);
        assert_eq!(r.tpm2b::<32>().unwrap_err(), Fmt1::Size);
        let mut r = Reader::new(&[0, 4, 1, 2]);
        assert_eq!(r.tpm2b::<32>().unwrap_err(), Fmt1::Insufficient);
        let mut r = Reader::new(&[0, 2, 1, 2, 9]);
        assert_eq!(r.tpm2b::<32>().unwrap().get(), &[1, 2]);
        assert_eq!(r.remaining(), 1);
    }

    #[test]
    fn trailing_zeros_are_trimmed_and_nothing_else() {
        let mut b = Buf::<8>::from_array([1, 0, 2, 0, 0]);
        b.trim_trailing_zeros();
        assert_eq!(b.as_slice(), &[1, 0, 2]);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// For every buffer of up to 8 bytes: a TPM2B read with bound 4 either fails without
    /// consuming past the buffer, or returns exactly the claimed bytes, never more than 4, and
    /// leaves the reader at the byte after them.
    #[kani::proof]
    #[kani::unwind(10)]
    fn tpm2b_reads_exactly_what_it_claims() {
        let data: [u8; 8] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 8);
        let mut r = Reader::new(&data[..len]);
        match r.tpm2b::<4>() {
            Ok(b) => {
                let claimed = u16::from_be_bytes([data[0], data[1]]) as usize;
                assert!(claimed <= 4);
                assert!(b.get().len() == claimed);
                assert!(r.remaining() == len - 2 - claimed);
                let i: usize = kani::any_where(|i| *i < claimed);
                assert!(b.get()[i] == data[2 + i]);
            }
            Err(Fmt1::Size) => {
                assert!(len >= 2 && u16::from_be_bytes([data[0], data[1]]) as usize > 4);
            }
            Err(Fmt1::Insufficient) => {
                assert!(len < 2 || u16::from_be_bytes([data[0], data[1]]) as usize > len - 2);
            }
            Err(_) => unreachable!(),
        }
    }

    /// Every fixed-width read consumes exactly its width or fails without overreading.
    #[kani::proof]
    fn fixed_width_reads_consume_their_width() {
        let data: [u8; 6] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 6);
        let mut r = Reader::new(&data[..len]);
        match r.u32() {
            Ok(v) => {
                assert!(len >= 4);
                assert!(v == u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                assert!(r.remaining() == len - 4);
            }
            Err(e) => {
                assert!(len < 4);
                assert!(e == Fmt1::Insufficient);
            }
        }
    }
}
