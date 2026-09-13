// SPDX-License-Identifier: Apache-2.0
//! Pinned SDK 6.7.0 HashableKey representations. Neither representation is an ELF hash.
use kai_volume_core::{Error, Hash, Result};
pub const KOALA_BEAR_MODULUS: u32 = 0x7f000001;

pub fn decode_hash_bytes(bytes: &[u8]) -> Result<[u32; 8]> {
    if bytes.len() != 32 {
        return Err(Error::Length("child key"));
    }
    let limbs =
        core::array::from_fn(|i| u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()));
    check_limbs(&limbs)?;
    Ok(limbs)
}
fn check_limbs(limbs: &[u32; 8]) -> Result<()> {
    if limbs.iter().any(|w| *w >= KOALA_BEAR_MODULUS) {
        return Err(Error::NonCanonical("VK KoalaBear limb"));
    }
    Ok(())
}
/// Left-padded big-endian sum(limb[i] * 2^(31*(7-i))).
pub fn pack31(limbs: &[u32; 8]) -> Result<Hash> {
    check_limbs(limbs)?;
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        for bit in 0..31 {
            let at = 8 + 31 * i + bit;
            out[at / 8] |= (((limb >> (30 - bit)) & 1) as u8) << (7 - at % 8);
        }
    }
    Ok(out)
}
pub fn unpack31(packed: &Hash) -> Result<[u32; 8]> {
    if packed[0] != 0 {
        return Err(Error::NonCanonical("VK exceeds 248 bits"));
    }
    let mut limbs = [0u32; 8];
    for (i, limb) in limbs.iter_mut().enumerate() {
        for bit in 0..31 {
            let at = 8 + 31 * i + bit;
            *limb = (*limb << 1) | u32::from((packed[at / 8] >> (7 - at % 8)) & 1);
        }
    }
    check_limbs(&limbs)?;
    Ok(limbs)
}
