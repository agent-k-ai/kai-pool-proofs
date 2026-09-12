// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Alpha Tech Organization
//! Borrowed canonical RLP helpers extracted from complete-race-core.
use crate::{ensure, Result};

#[derive(Clone, Copy, Debug)]
pub struct Item<'a> {
    pub raw: &'a [u8],
    pub data: &'a [u8],
    pub list: bool,
}

fn prefix(input: &[u8]) -> Result<(usize, usize, bool)> {
    ensure(!input.is_empty(), "RLP empty item")?;
    let p = input[0];
    if p < 0x80 {
        return Ok((0, 1, false));
    }
    let (off, len, list) = match p {
        0x80..=0xb7 => (1, (p - 0x80) as usize, false),
        0xc0..=0xf7 => (1, (p - 0xc0) as usize, true),
        _ => {
            let list = p >= 0xf8;
            let n = (p - if list { 0xf7 } else { 0xb7 }) as usize;
            ensure(input.len() > n && input[1] != 0, "RLP length prefix")?;
            let mut len = 0usize;
            for byte in &input[1..=n] {
                len = len
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(*byte as usize))
                    .ok_or("RLP length overflow")?;
            }
            ensure(len > 55, "RLP noncanonical long item")?;
            (1 + n, len, list)
        }
    };
    ensure(
        off.checked_add(len).is_some_and(|n| n <= input.len()),
        "RLP truncated item",
    )?;
    ensure(!(p == 0x81 && input[1] < 0x80), "RLP noncanonical byte")?;
    Ok((off, len, list))
}

pub fn item(input: &[u8]) -> Result<Item<'_>> {
    let (off, len, list) = prefix(input)?;
    ensure(off + len == input.len(), "RLP trailing bytes")?;
    Ok(Item {
        raw: input,
        data: &input[off..],
        list,
    })
}

pub fn list(input: &[u8]) -> Result<Vec<Item<'_>>> {
    let outer = item(input)?;
    ensure(outer.list, "RLP list required")?;
    let mut remaining = outer.data;
    let mut out = Vec::new();
    while !remaining.is_empty() {
        let (off, len, is_list) = prefix(remaining)?;
        let raw = &remaining[..off + len];
        out.push(Item {
            raw,
            data: &raw[off..],
            list: is_list,
        });
        remaining = &remaining[off + len..];
    }
    Ok(out)
}

pub fn data<'a>(i: &Item<'a>) -> Result<&'a [u8]> {
    ensure(!i.list, "RLP bytes required")?;
    Ok(i.data)
}

/// Every item, including a late malformed child, is checked on iteration.
pub struct Items<'a> {
    remaining: &'a [u8],
}
impl<'a> Items<'a> {
    pub fn new(encoded: &'a [u8]) -> Result<Self> {
        let outer = item(encoded)?;
        ensure(outer.list, "RLP list required")?;
        Ok(Self {
            remaining: outer.data,
        })
    }
}
impl<'a> Iterator for Items<'a> {
    type Item = Result<Item<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let result = prefix(self.remaining).map(|(off, len, list)| {
            let raw = &self.remaining[..off + len];
            self.remaining = &self.remaining[off + len..];
            Item {
                raw,
                data: &raw[off..],
                list,
            }
        });
        if result.is_err() {
            self.remaining = &[];
        }
        Some(result)
    }
}
