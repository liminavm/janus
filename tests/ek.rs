// SPDX-License-Identifier: MIT OR Apache-2.0

//! A provisioned EK certificate, as systemd-tpm2-setup (systemd 262, `tpm2_get_or_create_ek`)
//! finds and uses it: the certificate index's public area must carry the PC Client profile's
//! attributes, its data must read back, and the primary key the H-2 template makes in the
//! endorsement hierarchy must be the key the host certified, then persist at 0x81010001.
//! The guest must not be able to replace or delete it, and it must outlive a restore and a
//! reset.

use janus::{EkProfile, Janus, Locality, Platform, ProvisionError};

struct Zero;

impl Platform for Zero {
    fn fill_random(&mut self, buf: &mut [u8]) {
        buf.fill(0);
    }
    fn now_ms(&mut self) -> u64 {
        0
    }
}

const NO_SESSIONS: u16 = 0x8001;
const SESSIONS: u16 = 0x8002;
const OWNER: u32 = 0x4000_0001;
const ENDORSEMENT: u32 = 0x4000_000B;
const PLATFORM: u32 = 0x4000_000C;
const RS_PW: u32 = 0x4000_0009;
const CERT_INDEX: u32 = 0x01C0_0014;
const EK_HANDLE: u32 = 0x8101_0001;

/// Template H-2 as systemd 262 builds it (`tpm2_get_default_ek_template`), written out here
/// independently of janus's copy.
const H2: [u8; 58] = [
    0x00, 0x23, 0x00, 0x0b, 0x00, 0x03, 0x00, 0xf2, 0x00, 0x20, 0xca, 0x3d, 0x0a, 0x99, 0xa2, 0xb9,
    0x39, 0x06, 0xf7, 0xa3, 0x34, 0x24, 0x14, 0xef, 0xcf, 0xb3, 0xa3, 0x85, 0xd4, 0x4c, 0xd1, 0xfd,
    0x45, 0x90, 0x89, 0xd1, 0x9b, 0x50, 0x71, 0xc0, 0xb7, 0xa0, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
];

fn cmd(tag: u16, cc: u32, body: &[u8]) -> Vec<u8> {
    let mut v = tag.to_be_bytes().to_vec();
    v.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    v.extend_from_slice(&cc.to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn tpm2b(b: &[u8]) -> Vec<u8> {
    let mut v = (b.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v
}

/// One empty-password session, as an authorization area.
fn password() -> Vec<u8> {
    let mut s = RS_PW.to_be_bytes().to_vec();
    s.extend(tpm2b(&[]));
    s.push(0);
    s.extend(tpm2b(&[]));
    let mut v = (s.len() as u32).to_be_bytes().to_vec();
    v.extend(s);
    v
}

fn rc(rsp: &[u8]) -> u32 {
    u32::from_be_bytes(rsp[6..10].try_into().unwrap())
}

fn started(tpm: &mut Janus<Zero>) {
    tpm.init();
    let r = tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x144, &[0, 0]));
    assert_eq!(rc(&r), 0, "Startup(CLEAR)");
}

/// A certificate-shaped payload longer than one NV_Read moves.
fn certificate() -> Vec<u8> {
    (0..1500u32).map(|i| (i * 7 % 251) as u8).collect()
}

fn provisioned() -> Janus<Zero> {
    let mut tpm = Janus::manufacture(Zero);
    tpm.provision_ek_certificate(EkProfile::EccNistP256, &certificate()).unwrap();
    started(&mut tpm);
    tpm
}

/// `TPM2_NV_ReadPublic`: the index's attributes and size.
fn nv_read_public(tpm: &mut Janus<Zero>, index: u32) -> Result<(u32, u16), u32> {
    let r = tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x169, &index.to_be_bytes()));
    if rc(&r) != 0 {
        return Err(rc(&r));
    }
    // header, TPM2B size, nvIndex, nameAlg, attributes, authPolicy, dataSize
    let attrs = u32::from_be_bytes(r[18..22].try_into().unwrap());
    let policy = u16::from_be_bytes(r[22..24].try_into().unwrap()) as usize;
    let size = u16::from_be_bytes(r[24 + policy..26 + policy].try_into().unwrap());
    Ok((attrs, size))
}

/// The whole index, read under its own authorization in chunks, as tpm2-tss does.
fn nv_read_all(tpm: &mut Janus<Zero>, index: u32, size: u16) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < usize::from(size) {
        let n = (usize::from(size) - out.len()).min(1024) as u16;
        let mut body = index.to_be_bytes().to_vec();
        body.extend_from_slice(&index.to_be_bytes());
        body.extend(password());
        body.extend_from_slice(&n.to_be_bytes());
        body.extend_from_slice(&(out.len() as u16).to_be_bytes());
        let r = tpm.execute(Locality::ZERO, &cmd(SESSIONS, 0x14E, &body));
        assert_eq!(rc(&r), 0, "NV_Read at {}", out.len());
        // header, parameterSize, TPM2B data
        let len = u16::from_be_bytes(r[14..16].try_into().unwrap()) as usize;
        out.extend_from_slice(&r[16..16 + len]);
    }
    out
}

/// `TPM2_CreatePrimary(TPM_RH_ENDORSEMENT, H-2)`: the transient handle and the public point.
fn create_ek(tpm: &mut Janus<Zero>) -> (u32, Vec<u8>) {
    let mut body = ENDORSEMENT.to_be_bytes().to_vec();
    body.extend(password());
    body.extend(tpm2b(&[0, 0, 0, 0])); // inSensitive: empty userAuth and data
    body.extend(tpm2b(&H2));
    body.extend(tpm2b(&[])); // outsideInfo
    body.extend_from_slice(&0u32.to_be_bytes()); // creationPCR: none
    let r = tpm.execute(Locality::ZERO, &cmd(SESSIONS, 0x131, &body));
    assert_eq!(rc(&r), 0, "CreatePrimary(EK)");
    let handle = u32::from_be_bytes(r[10..14].try_into().unwrap());
    // header, handle, parameterSize, TPM2B size, then TPMT_PUBLIC: the unique point follows
    // 54 bytes of type, nameAlg, attributes, policy and parameters.
    let at = 20 + 54;
    let x_len = u16::from_be_bytes(r[at..at + 2].try_into().unwrap()) as usize;
    let x = &r[at + 2..at + 2 + x_len];
    let y_at = at + 2 + x_len;
    let y_len = u16::from_be_bytes(r[y_at..y_at + 2].try_into().unwrap()) as usize;
    let y = &r[y_at + 2..y_at + 2 + y_len];
    let mut point = vec![0x04];
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    (handle, point)
}

#[test]
fn systemd_finds_the_certificate_and_persists_the_matching_ek() {
    let mut tpm = provisioned();
    let (attrs, size) = nv_read_public(&mut tpm, CERT_INDEX).expect("the certificate index");

    // systemd's `has_expected_ek_cert_attributes`: an ordinary index, platformCreate, authRead
    // and noDA set, and none of authWrite, ownerWrite, globalLock, clearStClear, orderly,
    // readStClear.
    let set = 1 << 30 | 1 << 18 | 1 << 25;
    let clear = 1 << 2 | 1 << 1 | 1 << 15 | 1 << 27 | 1 << 26 | 1 << 31;
    assert_eq!(attrs >> 4 & 0xF, 0, "TPM_NT_ORDINARY");
    assert_eq!(attrs & set, set, "attributes {attrs:#x}");
    assert_eq!(attrs & clear, 0, "attributes {attrs:#x}");
    assert_ne!(attrs & 1 << 29, 0, "written");
    assert_ne!(attrs & 1 << 11, 0, "write-locked");

    assert_eq!(nv_read_all(&mut tpm, CERT_INDEX, size), certificate());

    let (ek, point) = create_ek(&mut tpm);
    assert_eq!(point, tpm.endorsement_key(EkProfile::EccNistP256), "the certified key");
    assert_eq!(point.len(), 65);

    let mut body = OWNER.to_be_bytes().to_vec();
    body.extend_from_slice(&ek.to_be_bytes());
    body.extend(password());
    body.extend_from_slice(&EK_HANDLE.to_be_bytes());
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &cmd(SESSIONS, 0x120, &body))), 0, "EvictControl");
    let r = tpm.execute(Locality::ZERO, &cmd(NO_SESSIONS, 0x173, &EK_HANDLE.to_be_bytes()));
    assert_eq!(rc(&r), 0, "ReadPublic of the persisted EK");
}

#[test]
fn the_guest_cannot_rewrite_or_delete_the_certificate() {
    let mut tpm = provisioned();
    // NV_Write by the platform: TPM_RC_NV_LOCKED.
    let mut body = PLATFORM.to_be_bytes().to_vec();
    body.extend_from_slice(&CERT_INDEX.to_be_bytes());
    body.extend(password());
    body.extend(tpm2b(&[0xAA; 16]));
    body.extend_from_slice(&0u16.to_be_bytes());
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &cmd(SESSIONS, 0x137, &body))), 0x148);
    // NV_UndefineSpace by the owner: TPM_RC_NV_AUTHORIZATION.
    let mut body = OWNER.to_be_bytes().to_vec();
    body.extend_from_slice(&CERT_INDEX.to_be_bytes());
    body.extend(password());
    assert_eq!(rc(&tpm.execute(Locality::ZERO, &cmd(SESSIONS, 0x122, &body))), 0x149);
    assert!(nv_read_public(&mut tpm, CERT_INDEX).is_ok());
}

#[test]
fn the_certificate_and_its_key_outlive_a_restore_and_a_reset() {
    let tpm = provisioned();
    let key = tpm.endorsement_key(EkProfile::EccNistP256);
    let mut tpm = Janus::restore(Zero, &tpm.state()).unwrap();
    assert!(tpm.has_ek_certificate(EkProfile::EccNistP256));
    assert_eq!(tpm.endorsement_key(EkProfile::EccNistP256), key);
    started(&mut tpm);
    let (attrs, size) = nv_read_public(&mut tpm, CERT_INDEX).unwrap();
    assert_ne!(attrs & 1 << 11, 0, "still write-locked after a Startup(CLEAR)");
    assert_eq!(nv_read_all(&mut tpm, CERT_INDEX, size), certificate());
}

#[test]
fn a_certificate_is_provisioned_once_and_within_an_index() {
    let mut tpm = Janus::manufacture(Zero);
    assert!(!tpm.has_ek_certificate(EkProfile::EccNistP256));
    let size = Err(ProvisionError::Size);
    assert_eq!(tpm.provision_ek_certificate(EkProfile::EccNistP256, &[]), size);
    assert_eq!(tpm.provision_ek_certificate(EkProfile::EccNistP256, &[1; 2049]), size);
    assert!(!tpm.has_ek_certificate(EkProfile::EccNistP256));
    tpm.provision_ek_certificate(EkProfile::EccNistP256, &[1; 2048]).unwrap();
    assert_eq!(
        tpm.provision_ek_certificate(EkProfile::EccNistP256, &[2; 10]),
        Err(ProvisionError::Defined)
    );
}
