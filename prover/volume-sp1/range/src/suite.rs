// SPDX-License-Identifier: Apache-2.0
//! Exact six-word VolumeProofSuiteV1 from SUITE-PREIMAGE-ADDENDUM.md.
use crate::key::unpack31;
use kai_volume_core::{keccak256, Address, Error, Hash, Result, VolumeTermsV1};
pub const SUITE_ABI_BYTES: usize = 192;
pub const CIRCUIT_IDENTITY: Hash = [
    0x43, 0x88, 0xa2, 0x1c, 0x68, 0x7f, 0xdd, 0x5f, 0x21, 0x8d, 0x7e, 0x3d, 0x13, 0x19, 0x0c, 0xac,
    0x4c, 0x53, 0x55, 0x81, 0x8d, 0x36, 0x05, 0xfd, 0x5f, 0xb8, 0x11, 0xdf, 0x46, 0x8e, 0xe6, 0x96,
];
pub fn suite_domain() -> Hash {
    keccak256(b"KAI_VOLUME_SP1_SUITE_V1")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeProofSuiteV1 {
    pub domain: Hash,
    pub chunk_program_vkey: Hash,
    pub range_program_vkey: Hash,
    pub sp1_verifier: Address,
    pub sp1_verifier_code_hash: Hash,
    pub circuit_identity: Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Chunk = 0,
    Range = 1,
}
impl TryFrom<u8> for Role {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Chunk),
            1 => Ok(Self::Range),
            _ => Err(Error::Invalid("child role")),
        }
    }
}
impl VolumeProofSuiteV1 {
    pub fn validate(&self) -> Result<()> {
        if self.domain != suite_domain()
            || self.chunk_program_vkey == [0; 32]
            || self.range_program_vkey == [0; 32]
            || self.chunk_program_vkey == self.range_program_vkey
        {
            return Err(Error::Invalid("suite domain/keys"));
        }
        unpack31(&self.chunk_program_vkey)?;
        unpack31(&self.range_program_vkey)?;
        if self.sp1_verifier == [0; 20]
            || self.sp1_verifier_code_hash == [0; 32]
            || self.circuit_identity != CIRCUIT_IDENTITY
        {
            return Err(Error::Invalid("suite verifier/circuit"));
        }
        Ok(())
    }
    pub fn abi_encode(&self) -> Result<[u8; SUITE_ABI_BYTES]> {
        self.validate()?;
        let mut out = [0u8; SUITE_ABI_BYTES];
        out[..32].copy_from_slice(&self.domain);
        out[32..64].copy_from_slice(&self.chunk_program_vkey);
        out[64..96].copy_from_slice(&self.range_program_vkey);
        out[108..128].copy_from_slice(&self.sp1_verifier);
        out[128..160].copy_from_slice(&self.sp1_verifier_code_hash);
        out[160..192].copy_from_slice(&self.circuit_identity);
        Ok(out)
    }
    pub fn abi_decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SUITE_ABI_BYTES {
            return Err(Error::Length("suite"));
        }
        if bytes[96..108] != [0; 12] {
            return Err(Error::NonCanonical("suite address padding"));
        }
        let s = Self {
            domain: bytes[..32].try_into().unwrap(),
            chunk_program_vkey: bytes[32..64].try_into().unwrap(),
            range_program_vkey: bytes[64..96].try_into().unwrap(),
            sp1_verifier: bytes[108..128].try_into().unwrap(),
            sp1_verifier_code_hash: bytes[128..160].try_into().unwrap(),
            circuit_identity: bytes[160..].try_into().unwrap(),
        };
        s.validate()?;
        Ok(s)
    }
    pub fn suite_hash(&self) -> Result<Hash> {
        Ok(keccak256(&self.abi_encode()?))
    }
    pub fn validate_terms(&self, terms: &VolumeTermsV1) -> Result<()> {
        terms.validate()?;
        if self.suite_hash()? != terms.proof_suite_hash
            || self.sp1_verifier != terms.sp1_verifier
            || self.sp1_verifier_code_hash != terms.sp1_verifier_code_hash
            || self.circuit_identity != terms.circuit_identity
        {
            return Err(Error::Invalid("suite/terms binding"));
        }
        Ok(())
    }
    pub fn role_key(&self, role: Role) -> Hash {
        match role {
            Role::Chunk => self.chunk_program_vkey,
            Role::Range => self.range_program_vkey,
        }
    }
}
