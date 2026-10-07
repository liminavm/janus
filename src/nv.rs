// SPDX-License-Identifier: MIT OR Apache-2.0

//! NV indexes: `TPM2_NV_DefineSpace`, `TPM2_NV_UndefineSpace`, `TPM2_NV_Write`,
//! `TPM2_NV_Extend`, `TPM2_NV_Read` and `TPM2_NV_ReadPublic`.
//!
//! An index is defined by an owner or the platform, holds `dataSize` bytes, and is read and
//! written under the authorizations its attributes allow. janus implements the ordinary and
//! extend types (`TPM_NT_ORDINARY`, `TPM_NT_EXTEND`): systemd-pcrlock keeps its policy in extend
//! indexes, and everything else the guests use is ordinary. Counter, bit-field and PIN indexes
//! are refused at definition, as the reference refuses a type whose commands it lacks.

use crate::alg::{Hash, MAX_DIGEST};
use crate::handle::{handle_type, ht};
use crate::marshal::{Marshal, Unmarshal};
use crate::rc::{At, Fmt0, Fmt1, Rc};
use crate::session::AuthValue;
use crate::types::{Digest2b, Name2b};
use crate::wire::{Reader, Writer};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The largest index (`MAX_NV_INDEX_SIZE`).
pub const MAX_NV_INDEX_SIZE: u16 = 2048;
/// The most one NV_Read or NV_Write moves (`MAX_NV_BUFFER_SIZE`).
pub const MAX_NV_BUFFER_SIZE: usize = 1024;
/// Indexes janus keeps; one more is `TPM_RC_NV_SPACE`.
pub const MAX_NV_INDEXES: usize = 64;

wire_bits! {
    /// `TPMA_NV`. `TPM_NT` is bits 4 to 7; bits 8, 9 and 20 to 24 are reserved.
    pub struct NvAttributes(u32) reserved 0x01F0_0300; {
        pp_write = 0,
        owner_write = 1,
        auth_write = 2,
        policy_write = 3,
        policy_delete = 10,
        write_locked = 11,
        write_all = 12,
        write_define = 13,
        write_stclear = 14,
        global_lock = 15,
        pp_read = 16,
        owner_read = 17,
        auth_read = 18,
        policy_read = 19,
        no_da = 25,
        orderly = 26,
        clear_stclear = 27,
        read_locked = 28,
        written = 29,
        platform_create = 30,
        read_stclear = 31,
    }
}

const WRITTEN: u32 = 1 << 29;
const WRITE_LOCKED: u32 = 1 << 11;
const READ_LOCKED: u32 = 1 << 28;

/// The index types janus implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvType {
    Ordinary,
    Extend,
}

impl NvAttributes {
    /// `TPM_NT`: `None` for a type janus does not implement.
    pub const fn kind(self) -> Option<NvType> {
        match (self.0 >> 4) & 0xF {
            0 => Some(NvType::Ordinary),
            4 => Some(NvType::Extend),
            _ => None,
        }
    }

    const fn with(self, bit: u32, on: bool) -> NvAttributes {
        NvAttributes(if on { self.0 | bit } else { self.0 & !bit })
    }
}

/// `TPMS_NV_PUBLIC`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvPublic {
    pub index: u32,
    pub name_alg: Hash,
    pub attributes: NvAttributes,
    pub auth_policy: Digest2b,
    pub data_size: u16,
}

impl Marshal for NvPublic {
    fn write(&self, w: &mut Writer) {
        w.u32(self.index);
        self.name_alg.write(w);
        self.attributes.write(w);
        self.auth_policy.write(w);
        w.u16(self.data_size);
    }
}

impl Unmarshal for NvPublic {
    /// `TPMI_RH_NV_INDEX` (`TPM_RC_VALUE`), `TPMI_ALG_HASH`, `TPMA_NV`, the policy, and a size
    /// no larger than an index may be (`TPM_RC_SIZE`).
    fn read(r: &mut Reader<'_>) -> Result<NvPublic, Fmt1> {
        let index = r.u32()?;
        if handle_type(index) != ht::NV_INDEX {
            return Err(Fmt1::Value);
        }
        let name_alg = Hash::read(r)?;
        let attributes = NvAttributes::read(r)?;
        let auth_policy = Digest2b::read(r)?;
        let data_size = r.u16()?;
        if data_size > MAX_NV_INDEX_SIZE {
            return Err(Fmt1::Size);
        }
        Ok(NvPublic { index, name_alg, attributes, auth_policy, data_size })
    }
}

impl NvPublic {
    /// The index's name: its name algorithm, then the digest of its marshalled public area. It
    /// changes when the area does (`TPMA_NV_WRITTEN`, the locks).
    pub fn name(&self) -> Name2b {
        let mut area = Writer::new();
        self.write(&mut area);
        let digest = self.name_alg.digest(&[&area.into_vec()]);
        let mut w = Writer::new();
        self.name_alg.write(&mut w);
        w.bytes(digest.as_slice());
        Name2b::from_slice(&w.into_vec()).expect("a name is at most a TPMT_HA")
    }
}

/// A defined index.
pub struct NvIndex {
    pub public: NvPublic,
    pub auth: AuthValue,
    /// `dataSize` bytes; meaningful once `TPMA_NV_WRITTEN` is set.
    data: Zeroizing<Vec<u8>>,
}

impl NvIndex {
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// A handle of a defined index. Only [`NvStore::find`] makes one, so a handler holding one
/// knows the index was defined when the command started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvRef(u32);

/// The bytes `len` long at `offset` of an index `data_size` long, as NV_Read and NV_Write check
/// them: an offset past the end is `TPM_RC_VALUE` on it (the second parameter of both), and a
/// range past the end `TPM_RC_NV_RANGE`.
fn within(data_size: usize, offset: u16, len: usize) -> Result<core::ops::Range<usize>, Rc> {
    let offset = usize::from(offset);
    if offset > data_size {
        return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(2))));
    }
    if len > data_size - offset {
        return Err(Fmt0::NvRange.into());
    }
    Ok(offset..offset + len)
}

/// Who authorized an NV read or write (`TPMI_RH_NV_AUTH`): the owner, the platform, the index
/// itself, or another index, which is accepted on the wire and authorized, then refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvAuth {
    Owner,
    Platform,
    Index,
    OtherIndex,
}

/// The defined indexes, by handle. They survive every reset; `TPM2_Startup` adjusts their
/// attributes ([`NvStore::startup`]).
#[derive(Default)]
pub struct NvStore {
    indexes: BTreeMap<u32, NvIndex>,
}

/// Where a refused definition is blamed: the authorization handle, the authValue, the public
/// area.
const BLAME_HANDLE: At = At::handle(1);
const BLAME_AUTH: At = At::param(1);
const BLAME_PUBLIC: At = At::param(2);

impl NvStore {
    pub fn find(&self, h: u32) -> Option<NvRef> {
        self.indexes.contains_key(&h).then_some(NvRef(h))
    }

    pub fn get(&self, n: NvRef) -> &NvIndex {
        self.indexes.get(&n.0).expect("an NvRef names a defined index")
    }

    /// The defined indexes' handles at or above `from`, in order.
    pub fn handles_from(&self, from: u32) -> Vec<u32> {
        self.indexes.range(from..).map(|(h, _)| *h).collect()
    }

    /// `TPM2_NV_DefineSpace`, with `NvDefineSpace`'s checks in its order. `platform` says the
    /// platform authorized it rather than the owner.
    pub fn define(&mut self, platform: bool, auth: &[u8], public: NvPublic) -> Result<(), Rc> {
        let attrs = public.attributes;
        let refuse = |code, at| Err(Rc::Fmt1(code, Some(at)));
        // No TPM2_NV_UndefineSpaceSpecial, so no index it alone could delete.
        if attrs.policy_delete() {
            return refuse(Fmt1::Attributes, BLAME_PUBLIC);
        }
        let digest = public.name_alg.size();
        let policy = public.auth_policy.as_slice().len();
        if policy != 0 && policy != digest {
            return refuse(Fmt1::Size, BLAME_PUBLIC);
        }
        let auth = AuthValue::from_slice(auth);
        if auth.key_material().len() > digest {
            return refuse(Fmt1::Size, BLAME_AUTH);
        }
        let Some(kind) = attrs.kind() else {
            return refuse(Fmt1::Attributes, BLAME_PUBLIC);
        };
        let size_ok = match kind {
            NvType::Ordinary => public.data_size <= MAX_NV_INDEX_SIZE,
            NvType::Extend => usize::from(public.data_size) == digest,
        };
        if !size_ok {
            return refuse(Fmt1::Size, BLAME_PUBLIC);
        }
        if attrs.written() || attrs.write_locked() || attrs.read_locked() {
            return refuse(Fmt1::Attributes, BLAME_PUBLIC);
        }
        let readable =
            attrs.owner_read() || attrs.pp_read() || attrs.auth_read() || attrs.policy_read();
        let writable =
            attrs.owner_write() || attrs.pp_write() || attrs.auth_write() || attrs.policy_write();
        if !readable || !writable {
            return refuse(Fmt1::Attributes, BLAME_PUBLIC);
        }
        if attrs.clear_stclear() && attrs.write_define() {
            return refuse(Fmt1::Attributes, BLAME_PUBLIC);
        }
        if attrs.platform_create() != platform {
            return refuse(Fmt1::Attributes, BLAME_HANDLE);
        }
        if usize::from(public.data_size) > MAX_NV_BUFFER_SIZE && attrs.write_all() {
            return refuse(Fmt1::Size, BLAME_PUBLIC);
        }
        if self.indexes.contains_key(&public.index) {
            return Err(Fmt0::NvDefined.into());
        }
        if self.indexes.len() == MAX_NV_INDEXES {
            return Err(Fmt0::NvSpace.into());
        }
        let data = Zeroizing::new(vec![0; usize::from(public.data_size)]);
        self.indexes.insert(public.index, NvIndex { public, auth, data });
        Ok(())
    }

    /// `TPM2_NV_UndefineSpace`: an index the platform made needs the platform.
    pub fn undefine(&mut self, platform: bool, n: NvRef) -> Result<(), Rc> {
        let attrs = self.get(n).public.attributes;
        if attrs.policy_delete() {
            return Err(Rc::Fmt1(Fmt1::Attributes, Some(At::handle(2))));
        }
        if !platform && attrs.platform_create() {
            return Err(Fmt0::NvAuthorization.into());
        }
        self.indexes.remove(&n.0);
        Ok(())
    }

    /// `NvWriteAccessChecks` and the common checks of `TPM2_NV_Write` and `TPM2_NV_Extend`.
    fn writable(&self, by: NvAuth, n: NvRef) -> Result<&NvIndex, Rc> {
        let index = self.get(n);
        let a = index.public.attributes;
        if a.write_locked() {
            return Err(Fmt0::NvLocked.into());
        }
        let allowed = match by {
            NvAuth::Owner => a.owner_write(),
            NvAuth::Platform => a.pp_write(),
            NvAuth::Index => true,
            NvAuth::OtherIndex => false,
        };
        if !allowed {
            return Err(Fmt0::NvAuthorization.into());
        }
        Ok(index)
    }

    /// `TPM2_NV_Write`: `data` at `offset` of an ordinary index. Returns whether the index was
    /// `TPMA_NV_ORDERLY`, which makes the last orderly shutdown stale.
    pub fn write(&mut self, by: NvAuth, n: NvRef, data: &[u8], offset: u16) -> Result<bool, Rc> {
        let index = self.writable(by, n)?;
        let a = index.public.attributes;
        if a.kind() != Some(NvType::Ordinary) {
            return Err(Rc::Fmt1(Fmt1::Attributes, None));
        }
        let size = usize::from(index.public.data_size);
        let range = within(size, offset, data.len())?;
        if a.write_all() && data.len() < size {
            return Err(Fmt0::NvRange.into());
        }
        let index = self.indexes.get_mut(&n.0).expect("an NvRef names a defined index");
        if !a.written() {
            // An ordinary index reads as zeros wherever its first write did not reach.
            index.data.fill(0);
            index.public.attributes = a.with(WRITTEN, true);
        }
        index.data[range].copy_from_slice(data);
        Ok(a.orderly())
    }

    /// `TPM2_NV_Extend`: the index becomes `H(old || data)`, `old` being zeros before the first
    /// extend. Returns whether the index was `TPMA_NV_ORDERLY`.
    pub fn extend(&mut self, by: NvAuth, n: NvRef, data: &[u8]) -> Result<bool, Rc> {
        let index = self.writable(by, n)?;
        let a = index.public.attributes;
        if a.kind() != Some(NvType::Extend) {
            return Err(Rc::Fmt1(Fmt1::Attributes, Some(At::handle(2))));
        }
        let zeros = [0u8; MAX_DIGEST];
        let old = if a.written() { index.data() } else { &zeros[..index.data.len()] };
        let new = index.public.name_alg.digest(&[old, data]);
        let index = self.indexes.get_mut(&n.0).expect("an NvRef names a defined index");
        index.data.copy_from_slice(new.as_slice());
        index.public.attributes = a.with(WRITTEN, true);
        Ok(a.orderly())
    }

    /// `TPM2_NV_Read`, with `NvReadAccessChecks` first.
    pub fn read(&self, by: NvAuth, n: NvRef, size: u16, offset: u16) -> Result<&[u8], Rc> {
        let index = self.get(n);
        let a = index.public.attributes;
        if a.read_locked() {
            return Err(Fmt0::NvLocked.into());
        }
        let allowed = match by {
            NvAuth::Owner => a.owner_read(),
            NvAuth::Platform => a.pp_read(),
            NvAuth::Index => true,
            NvAuth::OtherIndex => false,
        };
        if !allowed {
            return Err(Fmt0::NvAuthorization.into());
        }
        if !a.written() {
            return Err(Fmt0::NvUninitialized.into());
        }
        let size = usize::from(size);
        if size > MAX_NV_BUFFER_SIZE {
            return Err(Rc::Fmt1(Fmt1::Value, Some(At::param(1))));
        }
        Ok(&index.data[within(index.data.len(), offset, size)?])
    }

    /// `NvEntityStartup` for a Restart (`reset` false) or a Reset (`reset` true); a Resume
    /// changes nothing. Read locks always end; an index that clears at Startup, or an orderly
    /// one at a Reset, is unwritten again; a write lock ends unless the index is written and
    /// locked until it is undefined (`TPMA_NV_WRITEDEFINE`).
    pub fn startup(&mut self, reset: bool) {
        for index in self.indexes.values_mut() {
            let mut a = index.public.attributes.with(READ_LOCKED, false);
            if a.clear_stclear() || (a.orderly() && reset) {
                a = a.with(WRITTEN, false);
            }
            if !a.written() || !a.write_define() {
                a = a.with(WRITE_LOCKED, false);
            }
            index.public.attributes = a;
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::marshal::{read_prefix, round_trips};

    /// For every index size, offset and length: a range is given exactly when it lies inside the
    /// index, and it is then exactly `len` bytes from `offset`.
    #[kani::proof]
    fn an_nv_range_is_inside_the_index_or_refused() {
        let data_size: usize = kani::any_where(|n| *n <= MAX_NV_INDEX_SIZE as usize);
        let offset: u16 = kani::any();
        let len: usize = kani::any_where(|n| *n <= MAX_NV_BUFFER_SIZE);
        match within(data_size, offset, len) {
            Ok(r) => {
                assert!(r.start == offset as usize && r.len() == len && r.end <= data_size);
            }
            Err(_) => assert!(offset as usize + len > data_size),
        }
    }

    /// For every input of up to 16 bytes, `TPMS_NV_PUBLIC` reads only an NV index handle, a
    /// size an index may have and no reserved attribute, and writes back what it read.
    #[kani::proof]
    #[kani::unwind(18)]
    fn an_nv_public_area_reads_only_what_an_index_may_be() {
        let data: [u8; 16] = kani::any();
        let len: usize = kani::any_where(|l| *l <= 16);
        if let Ok((p, _)) = read_prefix::<NvPublic>(&data[..len]) {
            assert!(handle_type(p.index) == ht::NV_INDEX);
            assert!(p.data_size <= MAX_NV_INDEX_SIZE);
            assert!(p.attributes.bits() & NvAttributes::RESERVED == 0);
        }
        assert!(round_trips::<NvPublic>(&data[..len]));
    }
}
