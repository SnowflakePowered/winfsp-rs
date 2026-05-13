//! Extended-attribute support for the in-memory file system.
//!
//! Mirrors `MEMFS_FILE_NODE_EA_MAP` and the surrounding helpers from
//! memfs.cpp: a per-node, case-insensitive map of EA name → record.
//! Buffers are walked / emitted using the on-disk `FILE_FULL_EA_INFORMATION`
//! layout that WinFSP / NTFS use.

use std::collections::BTreeMap;

use windows::Win32::Foundation::STATUS_INVALID_PARAMETER;
use winfsp::FspError;
use winfsp_sys::{FspFileSystemAddEa, PFILE_FULL_EA_INFORMATION};

/// Bit set by the kernel when an EA must be understood by the caller.
pub const FILE_NEED_EA: u8 = 0x80;
/// `CreateOptions` bit: caller has declared no knowledge of EAs.
pub const FILE_NO_EA_KNOWLEDGE: u32 = 0x0000_0200;

/// One in-memory extended attribute.
#[derive(Clone, Debug)]
pub struct MemFsEa {
    pub flags: u8,
    /// EA name as stored on disk (case preserved, no trailing NUL).
    pub name: Vec<u8>,
    /// EA value bytes.
    pub value: Vec<u8>,
}

impl MemFsEa {
    /// Returns the NTFS "packed size" charged against the file's reported
    /// `EaSize` — `5 + EaNameLength + EaValueLength` per
    /// `FspFileSystemGetEaPackedSize`.
    pub fn packed_size(&self) -> u32 {
        5 + self.name.len() as u32 + self.value.len() as u32
    }
}

/// Convert an EA name to its case-insensitive lookup key (ASCII upper-case).
/// EA names are ASCII by convention on NTFS, so the simpler fold is
/// sufficient.
pub fn ea_key(name: &[u8]) -> Vec<u8> {
    name.iter().map(|b| b.to_ascii_uppercase()).collect()
}

/// Iterator over `FILE_FULL_EA_INFORMATION` records in a serialised buffer.
///
/// Each entry is decoded into an owned [`MemFsEa`]; `NextEntryOffset` is
/// honoured for chaining and the iterator stops as soon as a record's
/// `NextEntryOffset` is zero or the buffer ends.
pub struct EaIter<'a> {
    buf: &'a [u8],
    pos: Option<usize>,
}

impl<'a> EaIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: if buf.is_empty() { None } else { Some(0) },
        }
    }
}

impl<'a> Iterator for EaIter<'a> {
    type Item = Result<MemFsEa, FspError>;

    fn next(&mut self) -> Option<Self::Item> {
        let pos = self.pos?;
        let buf = self.buf;
        if pos + 8 > buf.len() {
            self.pos = None;
            return Some(Err(FspError::NTSTATUS(STATUS_INVALID_PARAMETER.0)));
        }
        let next_offset =
            u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
        let flags = buf[pos + 4];
        let name_len = buf[pos + 5] as usize;
        let value_len = u16::from_le_bytes([buf[pos + 6], buf[pos + 7]]) as usize;

        let name_start = pos + 8;
        let value_start = name_start + name_len + 1; // skip trailing NUL
        let value_end = value_start + value_len;
        if value_end > buf.len() {
            self.pos = None;
            return Some(Err(FspError::NTSTATUS(STATUS_INVALID_PARAMETER.0)));
        }

        let ea = MemFsEa {
            flags,
            name: buf[name_start..name_start + name_len].to_vec(),
            value: buf[value_start..value_end].to_vec(),
        };

        self.pos = match next_offset {
            0 => None,
            n if n.checked_add(pos).map_or(true, |p| p >= buf.len()) => None,
            n => Some(pos + n),
        };

        Some(Ok(ea))
    }
}

/// Add a single EA to an output buffer using WinFSP's alignment-aware helper.
/// Returns `true` if the EA was appended, `false` if it did not fit.
pub fn add_to_buffer(ea: &MemFsEa, buffer: &mut [u8], cursor: &mut u32) -> bool {
    // Build a FILE_FULL_EA_INFORMATION-shaped record on the stack-ish heap
    // and hand it to the WinFSP helper, which copies it into `buffer` at the
    // correct alignment.
    let total = 8 + ea.name.len() + 1 + ea.value.len();
    let mut record = vec![0u8; total];
    record[4] = ea.flags;
    record[5] = ea.name.len() as u8;
    record[6..8].copy_from_slice(&(ea.value.len() as u16).to_le_bytes());
    record[8..8 + ea.name.len()].copy_from_slice(&ea.name);
    // record[8 + name_len] stays 0 (NUL terminator).
    record[8 + ea.name.len() + 1..].copy_from_slice(&ea.value);

    unsafe {
        FspFileSystemAddEa(
            record.as_mut_ptr() as PFILE_FULL_EA_INFORMATION,
            buffer.as_mut_ptr() as PFILE_FULL_EA_INFORMATION,
            buffer.len() as u32,
            cursor as *mut u32,
        ) != 0
    }
}

/// Finalize the EA output buffer (writes the terminator zero-offset entry).
pub fn finalize_buffer(buffer: &mut [u8], cursor: &mut u32) {
    unsafe {
        FspFileSystemAddEa(
            std::ptr::null_mut(),
            buffer.as_mut_ptr() as PFILE_FULL_EA_INFORMATION,
            buffer.len() as u32,
            cursor as *mut u32,
        );
    }
    // The return value is intentionally ignored: when finalising the trailer
    // we don't fail if there's no room — the caller already has `cursor` set
    // to whatever fit.
}

/// Replace or insert an EA into `map`, returning the change to the file's
/// reported `EaSize` (positive when growing, negative when shrinking).
///
/// Matches `MemfsFileNodeSetEa`: a zero-length value removes the entry.
pub fn apply_set(map: &mut BTreeMap<Vec<u8>, MemFsEa>, ea: &MemFsEa) -> i64 {
    let key = ea_key(&ea.name);
    let plus = if ea.value.is_empty() {
        0
    } else {
        ea.packed_size() as i64
    };
    let minus = match map.remove(&key) {
        Some(existing) => existing.packed_size() as i64,
        None => 0,
    };
    if !ea.value.is_empty() {
        map.insert(key, ea.clone());
    }
    plus - minus
}

/// Returns `true` if any entry has [`FILE_NEED_EA`] set.
pub fn has_need_ea(map: &BTreeMap<Vec<u8>, MemFsEa>) -> bool {
    map.values().any(|ea| (ea.flags & FILE_NEED_EA) != 0)
}
