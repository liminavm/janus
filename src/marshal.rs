// SPDX-License-Identifier: MIT OR Apache-2.0

//! Marshalling, generated from one description per structure.
//!
//! Every TPM structure is described once, as a Rust type whose fields are other marshallable
//! types, and [`wire_struct!`] and [`wire_union!`] emit both directions from that description.
//! Reading and writing a structure therefore cannot disagree about its fields or their order,
//! and validation lives in the field types: a [`crate::alg::Hash`] field rejects an unimplemented
//! hash because reading one is how a `Hash` is made.
//!
//! The canonical-encoding property — reading a value and writing it back reproduces exactly the
//! bytes that were read — is what the `marshal` fuzz target and the proofs below hold every
//! type to.

use crate::rc::Fmt1;
use crate::wire::{Buf, Reader, Writer};

/// A value with a wire form.
pub trait Marshal {
    fn write(&self, w: &mut Writer);
}

/// A value read from guest bytes. Reading validates: a value that exists is a valid one.
pub trait Unmarshal: Sized {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1>;
}

impl Marshal for () {
    fn write(&self, _: &mut Writer) {}
}

impl Unmarshal for () {
    fn read(_: &mut Reader<'_>) -> Result<(), Fmt1> {
        Ok(())
    }
}

macro_rules! fixed_width {
    ($($t:ident),*) => {$(
        impl Marshal for $t {
            fn write(&self, w: &mut Writer) {
                w.$t(*self);
            }
        }

        impl Unmarshal for $t {
            fn read(r: &mut Reader<'_>) -> Result<$t, Fmt1> {
                r.$t()
            }
        }
    )*};
}

fixed_width!(u8, u16, u32, u64);

impl<T: Marshal + ?Sized> Marshal for &T {
    fn write(&self, w: &mut Writer) {
        (**self).write(w);
    }
}

/// A flag: one byte, 0 or 1 (`TPMI_YES_NO`); anything else is `TPM_RC_VALUE`.
impl Marshal for bool {
    fn write(&self, w: &mut Writer) {
        w.u8(u8::from(*self));
    }
}

impl Unmarshal for bool {
    fn read(r: &mut Reader<'_>) -> Result<bool, Fmt1> {
        match r.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Fmt1::Value),
        }
    }
}

/// An optional value in janus's own formats (saved contexts, the state file): a presence flag,
/// then the value. No TPM structure uses this encoding.
impl<T: Marshal> Marshal for Option<T> {
    fn write(&self, w: &mut Writer) {
        self.is_some().write(w);
        if let Some(t) = self {
            t.write(w);
        }
    }
}

impl<T: Unmarshal> Unmarshal for Option<T> {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        if bool::read(r)? { Ok(Some(T::read(r)?)) } else { Ok(None) }
    }
}

/// A fixed number of bytes, with no size field.
impl<const N: usize> Marshal for [u8; N] {
    fn write(&self, w: &mut Writer) {
        w.bytes(self);
    }
}

impl<const N: usize> Unmarshal for [u8; N] {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        let mut a = [0u8; N];
        a.copy_from_slice(r.bytes(N)?);
        Ok(a)
    }
}

/// A `TPM2B` of plain bytes: a size, then at most `MAX` bytes.
impl<const MAX: usize> Marshal for Buf<MAX> {
    fn write(&self, w: &mut Writer) {
        w.tpm2b(self.as_slice());
    }
}

impl<const MAX: usize> Unmarshal for Buf<MAX> {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        Ok(Buf::from_wire(r.tpm2b::<MAX>()?))
    }
}

/// A `TPM2B` that wraps a structure (`TPM2B_PUBLIC`, `TPM2B_SENSITIVE_CREATE`, ...): a size,
/// then exactly that many bytes holding one `T`.
///
/// The size and the structure are one value: the size is never stored, it is what `T` writes.
/// A zero size, or a structure that does not fill the size exactly, is `TPM_RC_SIZE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tpm2b<T>(pub T);

impl<T: Marshal> Marshal for Tpm2b<T> {
    fn write(&self, w: &mut Writer) {
        let mut inner = Writer::new();
        self.0.write(&mut inner);
        w.tpm2b(&inner.into_vec());
    }
}

impl<T: Unmarshal> Unmarshal for Tpm2b<T> {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        let n = usize::from(r.u16()?);
        if n == 0 {
            return Err(Fmt1::Size);
        }
        let mut inner = r.split(n)?;
        let t = T::read(&mut inner)?;
        inner.finish()?;
        Ok(Tpm2b(t))
    }
}

/// A `TPML_*`: a 32-bit count, then that many entries, at most `MAX` (else `TPM_RC_SIZE`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> List<T, MAX> {
    /// `None` when `v` is longer than the list may be.
    pub fn new(v: Vec<T>) -> Option<Self> {
        (v.len() <= MAX).then_some(List(v))
    }

    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T: Marshal, const MAX: usize> Marshal for List<T, MAX> {
    fn write(&self, w: &mut Writer) {
        w.u32(u32::try_from(self.0.len()).expect("a list longer than its bound"));
        for e in &self.0 {
            e.write(w);
        }
    }
}

impl<T: Unmarshal, const MAX: usize> Unmarshal for List<T, MAX> {
    fn read(r: &mut Reader<'_>) -> Result<Self, Fmt1> {
        let n = r.u32()? as usize;
        if n > MAX {
            return Err(Fmt1::Size);
        }
        (0..n).map(|_| T::read(r)).collect::<Result<_, _>>().map(List)
    }
}

/// A structure: its fields in wire order, each a marshallable type.
///
/// ```ignore
/// wire_struct! {
///     /// TPMS_ECC_POINT
///     pub struct EccPoint {
///         pub x: Buf<32>,
///         pub y: Buf<32>,
///     }
/// }
/// ```
macro_rules! wire_struct {
    (
        $(#[$m:meta])*
        $vis:vis struct $name:ident {
            $( $(#[$fm:meta])* $fvis:vis $field:ident : $ty:ty ),* $(,)?
        }
    ) => {
        $(#[$m])*
        $vis struct $name {
            $( $(#[$fm])* $fvis $field: $ty ),*
        }

        impl $crate::marshal::Marshal for $name {
            #[allow(unused_variables)]
            fn write(&self, w: &mut $crate::wire::Writer) {
                $( $crate::marshal::Marshal::write(&self.$field, w); )*
            }
        }

        impl $crate::marshal::Unmarshal for $name {
            #[allow(unused_variables)]
            fn read(
                r: &mut $crate::wire::Reader<'_>,
            ) -> ::core::result::Result<Self, $crate::rc::Fmt1> {
                Ok($name { $( $field: $crate::marshal::Unmarshal::read(r)? ),* })
            }
        }
    };
}

/// A union with its selector (`TPMT_*` over a `TPMU_*`, or a `TPMI_*` of algorithm ids): a
/// Rust enum whose variant *is* the selector, so the two can never disagree. Each variant names
/// its selector value and the type of the body that follows it (`()` for none). A selector
/// outside the list is the error in brackets.
///
/// Besides the whole-value impls, the enum gets `selector()`, `write_body()` and `read_body()`,
/// for the one structure that puts fields between its selector and its body (`TPMT_PUBLIC`).
///
/// ```ignore
/// wire_union! {
///     /// TPMT_ECC_SCHEME
///     pub enum EccScheme: u16 [Fmt1::Scheme] {
///         Null = alg::NULL => (),
///         Ecdsa = alg::ECDSA => Hash,
///     }
/// }
/// ```
macro_rules! wire_union {
    (
        $(#[$m:meta])*
        $vis:vis enum $name:ident : $sel:ident [$err:expr] {
            $( $(#[$vm:meta])* $variant:ident = $value:expr => $body:ty ),+ $(,)?
        }
    ) => {
        $(#[$m])*
        $vis enum $name {
            $( $(#[$vm])* $variant($body) ),+
        }

        #[allow(dead_code)]
        impl $name {
            pub fn selector(&self) -> $sel {
                match self {
                    $( $name::$variant(_) => $value ),+
                }
            }

            pub fn write_body(&self, w: &mut $crate::wire::Writer) {
                match self {
                    $( $name::$variant(b) => $crate::marshal::Marshal::write(b, w) ),+
                }
            }

            /// Whether `selector` names a variant, for a structure that must reject its selector
            /// before reading the fields between it and the body.
            pub fn is_selector(selector: $sel) -> bool {
                $( selector == $value )||+
            }

            pub fn read_body(
                selector: $sel,
                r: &mut $crate::wire::Reader<'_>,
            ) -> ::core::result::Result<Self, $crate::rc::Fmt1> {
                $(
                    if selector == $value {
                        return Ok($name::$variant($crate::marshal::Unmarshal::read(r)?));
                    }
                )+
                Err($err)
            }
        }

        impl $crate::marshal::Marshal for $name {
            fn write(&self, w: &mut $crate::wire::Writer) {
                $crate::marshal::Marshal::write(&self.selector(), w);
                self.write_body(w);
            }
        }

        impl $crate::marshal::Unmarshal for $name {
            fn read(
                r: &mut $crate::wire::Reader<'_>,
            ) -> ::core::result::Result<Self, $crate::rc::Fmt1> {
                let selector = <$sel as $crate::marshal::Unmarshal>::read(r)?;
                Self::read_body(selector, r)
            }
        }
    };
}

/// An enumeration of values (`TPMI_*` without a body): a Rust enum whose variants are the
/// accepted values. Anything else is the error in brackets.
macro_rules! wire_values {
    (
        $(#[$m:meta])*
        $vis:vis enum $name:ident : $int:ident [$err:expr] {
            $( $(#[$vm:meta])* $variant:ident = $value:expr ),+ $(,)?
        }
    ) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        $vis enum $name {
            $( $(#[$vm])* $variant ),+
        }

        #[allow(dead_code)]
        impl $name {
            pub const fn value(self) -> $int {
                match self {
                    $( $name::$variant => $value ),+
                }
            }

            pub fn from_value(v: $int) -> Option<Self> {
                $( if v == $value { return Some($name::$variant); } )+
                None
            }
        }

        impl $crate::marshal::Marshal for $name {
            fn write(&self, w: &mut $crate::wire::Writer) {
                $crate::marshal::Marshal::write(&self.value(), w);
            }
        }

        impl $crate::marshal::Unmarshal for $name {
            fn read(
                r: &mut $crate::wire::Reader<'_>,
            ) -> ::core::result::Result<Self, $crate::rc::Fmt1> {
                let v = <$int as $crate::marshal::Unmarshal>::read(r)?;
                $name::from_value(v).ok_or($err)
            }
        }
    };
}

/// An attribute word (`TPMA_*`): a newtype over its integer whose reserved bits must be clear
/// (else `TPM_RC_RESERVED_BITS`), with a named accessor per bit.
macro_rules! wire_bits {
    (
        $(#[$m:meta])*
        $vis:vis struct $name:ident($int:ident) reserved $reserved:expr; {
            $( $(#[$bm:meta])* $bit:ident = $shift:expr ),* $(,)?
        }
    ) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        $vis struct $name($int);

        #[allow(dead_code)]
        impl $name {
            pub const RESERVED: $int = $reserved;

            /// `None` when a reserved bit is set.
            pub const fn new(v: $int) -> Option<Self> {
                if v & Self::RESERVED == 0 { Some($name(v)) } else { None }
            }

            pub const fn bits(self) -> $int {
                self.0
            }

            $(
                $(#[$bm])*
                pub const fn $bit(self) -> bool {
                    self.0 & (1 << $shift) != 0
                }
            )*
        }

        impl $crate::marshal::Marshal for $name {
            fn write(&self, w: &mut $crate::wire::Writer) {
                $crate::marshal::Marshal::write(&self.0, w);
            }
        }

        impl $crate::marshal::Unmarshal for $name {
            fn read(
                r: &mut $crate::wire::Reader<'_>,
            ) -> ::core::result::Result<Self, $crate::rc::Fmt1> {
                let v = <$int as $crate::marshal::Unmarshal>::read(r)?;
                $name::new(v).ok_or($crate::rc::Fmt1::ReservedBits)
            }
        }
    };
}

/// Reads one `T` from `bytes`, returning it with the number of bytes it took.
#[cfg(any(test, kani, fuzzing))]
pub fn read_prefix<T: Unmarshal>(bytes: &[u8]) -> Result<(T, usize), Fmt1> {
    let mut r = Reader::new(bytes);
    let t = T::read(&mut r)?;
    Ok((t, bytes.len() - r.remaining()))
}

/// The canonical-encoding property for one type and one input: if `bytes` begins with a valid
/// `T`, writing that `T` reproduces exactly the bytes it was read from.
#[cfg(any(test, kani, fuzzing))]
pub fn round_trips<T: Unmarshal + Marshal>(bytes: &[u8]) -> bool {
    match read_prefix::<T>(bytes) {
        Ok((t, n)) => {
            let mut w = Writer::new();
            t.write(&mut w);
            w.into_vec() == bytes[..n]
        }
        Err(_) => true,
    }
}

#[cfg(any(test, kani))]
mod probe {
    use crate::alg::Hash;
    use crate::rc::Fmt1;
    use crate::wire::Buf;

    wire_union! {
        /// A small union exercising every macro path: a unit body, a primitive body and a
        /// structure body.
        #[derive(Debug)]
        pub enum ProbeUnion: u16 [Fmt1::Selector] {
            Empty = 0x10 => (),
            Word = 0x11 => ProbeValue,
            Pair = 0x12 => ProbePair,
        }
    }

    wire_struct! {
        #[derive(Debug)]
        pub struct ProbePair {
            pub hash: Hash,
            pub data: Buf<3>,
        }
    }

    wire_values! {
        pub enum ProbeValue: u16 [Fmt1::Value] {
            One = 1,
            Two = 2,
        }
    }

    wire_bits! {
        pub struct ProbeBits(u8) reserved 0xF0; {
            low = 0,
        }
    }

    wire_struct! {
        #[derive(Debug)]
        pub struct Probe {
            pub bits: ProbeBits,
            pub union: ProbeUnion,
            pub tail: Buf<2>,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::probe::*;
    use super::*;

    #[test]
    fn a_struct_reads_its_fields_in_order_and_writes_them_back() {
        // bits 0x01; Pair: sha256, 2 bytes; tail: 1 byte; then a trailing byte not ours.
        let bytes = [0x01, 0x00, 0x12, 0x00, 0x0B, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x01, 0xCC, 0xEE];
        let (p, n) = read_prefix::<Probe>(&bytes).unwrap();
        assert_eq!(n, bytes.len() - 1);
        assert!(p.bits.low());
        match &p.union {
            ProbeUnion::Pair(pair) => assert_eq!(pair.data.as_slice(), &[0xAA, 0xBB]),
            other => panic!("read {other:?}"),
        }
        assert!(round_trips::<Probe>(&bytes));
    }

    #[test]
    fn each_field_type_rejects_with_its_own_code() {
        // A reserved attribute bit.
        assert_eq!(read_prefix::<Probe>(&[0x10]).unwrap_err(), Fmt1::ReservedBits);
        // An unknown selector.
        assert_eq!(read_prefix::<Probe>(&[0x00, 0x00, 0x13]).unwrap_err(), Fmt1::Selector);
        // An unimplemented hash inside the body.
        assert_eq!(read_prefix::<Probe>(&[0x00, 0x00, 0x12, 0x00, 0x04]).unwrap_err(), Fmt1::Hash);
        // A TPM2B over its bound.
        let over = [0x00, 0x00, 0x10, 0x00, 0x03, 1, 2, 3];
        assert_eq!(read_prefix::<Probe>(&over).unwrap_err(), Fmt1::Size);
    }

    #[test]
    fn a_sized_structure_must_fill_its_size_exactly() {
        // Size 3 around a u16: one byte left over.
        assert_eq!(read_prefix::<Tpm2b<u16>>(&[0, 3, 1, 2, 3]).unwrap_err(), Fmt1::Size);
        // Size 0.
        assert_eq!(read_prefix::<Tpm2b<u16>>(&[0, 0]).unwrap_err(), Fmt1::Size);
        // Size 1 around a u16: the structure runs out inside its size.
        assert_eq!(read_prefix::<Tpm2b<u16>>(&[0, 1, 1, 2]).unwrap_err(), Fmt1::Insufficient);
        assert!(round_trips::<Tpm2b<u16>>(&[0, 2, 1, 2]));
    }

    #[test]
    fn a_list_longer_than_its_bound_is_size() {
        assert_eq!(read_prefix::<List<u8, 2>>(&[0, 0, 0, 3, 1, 2, 3]).unwrap_err(), Fmt1::Size);
        assert!(round_trips::<List<u8, 2>>(&[0, 0, 0, 2, 1, 2]));
    }
}

#[cfg(kani)]
mod proofs {
    use super::probe::*;
    use super::*;

    /// For every input of up to 12 bytes, the probe — which exercises structures, unions with
    /// unit, primitive and structure bodies, attribute words and TPM2Bs — writes back exactly
    /// the bytes it read.
    #[kani::proof]
    #[kani::unwind(14)]
    fn generated_marshalling_is_canonical() {
        let data: [u8; 12] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 12);
        assert!(round_trips::<Probe>(&data[..len]));
    }

    /// A sized wrapper accepts exactly the inputs whose size field matches the structure.
    #[kani::proof]
    #[kani::unwind(8)]
    fn a_sized_wrapper_is_exactly_its_contents() {
        let data: [u8; 6] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 6);
        if let Ok((_, n)) = read_prefix::<Tpm2b<u16>>(&data[..len]) {
            assert!(n == 4);
            assert!(data[0] == 0 && data[1] == 2);
        }
        assert!(round_trips::<Tpm2b<u16>>(&data[..len]));
    }
}
