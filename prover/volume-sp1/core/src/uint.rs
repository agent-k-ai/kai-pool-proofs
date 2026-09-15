// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! Fixed-width big-endian values; no lossy numeric conversion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U256([u8; 32]);
impl U256 {
    pub const ZERO: Self = Self([0; 32]);
    pub const MAX: Self = Self([255; 32]);
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }
    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }
    pub fn from_u128(value: u128) -> Self {
        let mut bytes = [0; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
    pub fn checked_add(self, other: Self) -> Option<Self> {
        let mut bytes = [0; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let sum = self.0[i] as u16 + other.0[i] as u16 + carry;
            bytes[i] = sum as u8;
            carry = sum >> 8;
        }
        if carry == 0 {
            Some(Self(bytes))
        } else {
            None
        }
    }
}
impl From<u64> for U256 {
    fn from(value: u64) -> Self {
        Self::from_u128(value as u128)
    }
}
impl From<u128> for U256 {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

/// Two's-complement `int256` as one ABI word. Ordering is deliberately not derived:
/// byte order is not signed order. Only sign, zero test and magnitude are offered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct I256([u8; 32]);
impl I256 {
    pub const ZERO: Self = Self([0; 32]);
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }
    pub fn is_negative(self) -> bool {
        self.0[0] & 0x80 != 0
    }
    pub fn is_zero(self) -> bool {
        self == Self::ZERO
    }
    /// Magnitude as an unsigned word. `int256::MIN` has magnitude 2^255, which fits; no path overflows.
    pub fn unsigned_abs(self) -> U256 {
        if !self.is_negative() {
            return U256(self.0);
        }
        let mut bytes = [0; 32];
        let mut carry = 1u16;
        for i in (0..32).rev() {
            let sum = (!self.0[i]) as u16 + carry;
            bytes[i] = sum as u8;
            carry = sum >> 8;
        }
        U256(bytes)
    }
}
impl From<i128> for I256 {
    fn from(value: i128) -> Self {
        let mut bytes = [if value < 0 { 255 } else { 0 }; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
}
