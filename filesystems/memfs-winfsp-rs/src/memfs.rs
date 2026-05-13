//! In-memory file system port of `winfsp/tst/memfs/memfs.cpp`.
//!
//! Implements the `FileSystemContext` trait against an in-memory tree of
//! `MemFsNode` values keyed by [`NtfsPath`] (a thin wrapper around
//! `U16CStr` provided by this crate's `path` module). Named streams, reparse
//! points, extended attributes, the ROT13 device-control test, the WinFSP
//! "get directory info by name" optimisation, and slow-I/O delays are all
//! supported, as are WSL stat extensions (`FileStatInformation` /
//! `FileStatLxInformation` queries) once `WslFeatures` is on. This is now a
//! complete port of the in-tree memfs reference.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::ops::Bound::{Excluded, Unbounded};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use widestring::{U16CStr, U16Str};
use windows::Win32::Foundation::{
    HLOCAL, LocalFree, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
    STATUS_CANNOT_MAKE, STATUS_DIRECTORY_NOT_EMPTY, STATUS_DISK_FULL, STATUS_END_OF_FILE,
    STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER, STATUS_NOT_A_DIRECTORY,
    STATUS_NOT_A_REPARSE_POINT, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{GetSecurityDescriptorLength, PSECURITY_DESCRIPTOR};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    INVALID_FILE_ATTRIBUTES,
};
use windows::core::PCWSTR;
use winfsp::FspError;
use winfsp::constants::FspCleanupFlags;
use winfsp::filesystem::{
    AsyncFileSystemContext, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext,
    ModificationDescriptor, OpenFileInfo, StreamInfo, VolumeInfo, WideNameInfo,
};
use winfsp::host::{DebugMode, FileSystemHost, FileSystemParams, FineGuard, VolumeParams};
use winfsp_sys::{
    FspDeleteSecurityDescriptor, FspFileSystemCanReplaceReparsePoint, FspSetSecurityDescriptor,
};

use crate::ea::{self, FILE_NO_EA_KNOWLEDGE, MemFsEa, has_need_ea};
use crate::path::{BACKSLASH, COLON, NtfsPath, NtfsPathBuf};
use crate::slowio::Slowio;

pub const MEMFS_MAX_PATH: usize = 512;
const MEMFS_SECTOR_SIZE: u32 = 512;
const MEMFS_SECTORS_PER_ALLOCATION_UNIT: u32 = 1;
const ALLOCATION_UNIT: u64 =
    (MEMFS_SECTOR_SIZE as u64) * (MEMFS_SECTORS_PER_ALLOCATION_UNIT as u64);

bitflags::bitflags! {
    /// Configuration flags for [`MemFs::create`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemFsFlags: u32 {
        /// Use a case-insensitive file name comparator.
        const CASE_INSENSITIVE = 0x80000000;
        /// Ask WinFSP to flush and purge cached file data on cleanup.
        const FLUSH_AND_PURGE_ON_CLEANUP = 0x40000000;
        /// Disable POSIX unlink/rename semantics (legacy behaviour).
        const LEGACY_UNLINK_RENAME = 0x20000000;
    }
}

/// Configuration parameters for constructing a [`MemFs`].
#[derive(Clone, Debug)]
pub struct MemFsParams {
    pub flags: MemFsFlags,
    pub file_info_timeout: u32,
    pub max_file_nodes: u32,
    pub max_file_size: u32,
    pub file_system_name: Option<String>,
    pub volume_prefix: Option<String>,
    pub root_sddl: Option<String>,
    /// Maximum slow-I/O delay in milliseconds. `0` disables slow I/O entirely
    /// and the file system uses the synchronous host path.
    pub slowio_max_delay: u32,
    /// Probability (0–100) that a given I/O call has a delay applied.
    pub slowio_percent_delay: u32,
    /// Controls how rarefied the delays are: each call computes
    /// `random(max + 1) >> random(rarefy + 1)`, so higher values bias toward
    /// shorter delays.
    pub slowio_rarefy_delay: u32,
}

impl Default for MemFsParams {
    fn default() -> Self {
        Self {
            flags: MemFsFlags::empty(),
            file_info_timeout: u32::MAX,
            max_file_nodes: 1024,
            max_file_size: 16 * 1024 * 1024,
            file_system_name: None,
            volume_prefix: None,
            root_sddl: None,
            slowio_max_delay: 0,
            slowio_percent_delay: 0,
            slowio_rarefy_delay: 0,
        }
    }
}

/// Owner of the [`FileSystemHost`] and the in-memory state.
pub struct MemFs {
    pub fs: FileSystemHost<MemFsContext, FineGuard>,
}

impl MemFs {
    /// Create a new in-memory file system using the supplied parameters.
    pub fn create(params: MemFsParams) -> anyhow::Result<Self> {
        let case_insensitive = params.flags.contains(MemFsFlags::CASE_INSENSITIVE);
        let flush_and_purge = params
            .flags
            .contains(MemFsFlags::FLUSH_AND_PURGE_ON_CLEANUP);
        let supports_posix_unlink_rename = !params.flags.contains(MemFsFlags::LEGACY_UNLINK_RENAME);

        let max_file_size = ((params.max_file_size as u64 + ALLOCATION_UNIT - 1) / ALLOCATION_UNIT
            * ALLOCATION_UNIT) as u32;

        let mut volume_params = VolumeParams::new();
        volume_params
            .sector_size(MEMFS_SECTOR_SIZE as u16)
            .sectors_per_allocation_unit(MEMFS_SECTORS_PER_ALLOCATION_UNIT as u16)
            .volume_creation_time(system_time_filetime())
            .volume_serial_number((system_time_filetime() / (10_000 * 1000)) as u32)
            .file_info_timeout(params.file_info_timeout)
            .case_sensitive_search(!case_insensitive)
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .persistent_acls(true)
            .reparse_points(true)
            .reparse_points_access_check(false)
            .named_streams(true)
            .post_cleanup_when_modified_only(true)
            .post_disposition_only_when_necessary(true)
            .pass_query_directory_filename(true)
            .flush_and_purge_on_cleanup(flush_and_purge)
            .device_control(true)
            .extended_attributes(true)
            .wsl_features(true)
            .allow_open_in_kernel_mode(true)
            .supports_posix_unlink_rename(supports_posix_unlink_rename);

        if let Some(prefix) = params.volume_prefix.as_deref() {
            volume_params.prefix(prefix);
        }
        volume_params.filesystem_name(params.file_system_name.as_deref().unwrap_or("-MEMFS"));

        let slowio_enabled = params.slowio_max_delay > 0;
        let context = MemFsContext::new(
            case_insensitive,
            params.max_file_nodes,
            max_file_size,
            params.root_sddl.as_deref(),
            params.slowio_max_delay,
            params.slowio_percent_delay,
            params.slowio_rarefy_delay,
            slowio_enabled,
        )?;

        let fs_params = FileSystemParams {
            use_dir_info_by_name: true,
            volume_params,
            debug_mode: DebugMode::none(),
        };

        // When slow I/O is enabled we route read/write/read_directory through
        // the async vtable so the framework returns STATUS_PENDING to the
        // FSD and finishes the I/O after the tokio sleep resolves. Without
        // slow I/O we stick to the cheaper synchronous path.
        let host = if slowio_enabled {
            FileSystemHost::<MemFsContext, FineGuard>::new_with_options_async(fs_params, context)?
        } else {
            FileSystemHost::<MemFsContext, FineGuard>::new_with_options(fs_params, context)?
        };

        Ok(Self { fs: host })
    }
}

/// File context returned by `open`/`create`.
///
/// The context is just an integer handle into the live-node table; the actual
/// node data is owned by [`MemFsContext::state`].
#[derive(Clone, Copy, Debug)]
pub struct MemFsHandle(u64);

/// Filesystem-context type passed to WinFSP. All mutable state lives behind a
/// single [`Mutex`].
pub struct MemFsContext {
    state: Mutex<MemFsState>,
    case_insensitive: bool,
    max_file_nodes: u32,
    max_file_size: u32,
    slowio: Slowio,
    /// Multi-threaded tokio runtime used to back
    /// [`AsyncFileSystemContext::spawn_task`] when slow I/O is enabled. `None`
    /// when slow I/O is disabled — in that case the host is constructed
    /// through the synchronous path and the async vtable is never used.
    executor: Option<tokio::runtime::Runtime>,
}

struct MemFsState {
    /// Live nodes (both in-tree and detached-but-still-open).
    nodes: HashMap<u64, MemFsNode>,
    /// Path-aware ordered lookup table from canonicalized name to node id.
    by_name: BTreeMap<NtfsPathBuf, u64>,
    /// The next id we will assign to a new node.
    next_node_id: u64,
    /// The next `index_number` to hand out to a new node.
    next_index_number: u64,
    /// Volume label as UTF-16, length in bytes (without terminator).
    volume_label: Vec<u16>,
    /// Mirrored from the outer context so map helpers don't have to thread
    /// `case_insensitive` through every call.
    case_insensitive: bool,
}

struct MemFsNode {
    /// NUL-terminated wide path with original case preserved.
    file_name: NtfsPathBuf,
    file_info: FileInfo,
    file_security: Vec<u8>,
    file_data: Vec<u8>,
    reparse_data: Vec<u8>,
    /// Extended-attribute storage, keyed by ASCII-uppercase EA name.
    /// `FileInfo::ea_size` is kept in sync with the sum of packed sizes.
    ea_map: std::collections::BTreeMap<Vec<u8>, MemFsEa>,
    /// Node id of this stream's main file node, if this is a named stream.
    main_file_node: Option<u64>,
    /// Combined open-handle + presence-in-map refcount, matching
    /// `MEMFS_FILE_NODE::RefCount` in memfs.cpp.
    refcount: u32,
}

impl MemFsNode {
    fn path(&self) -> &NtfsPath {
        self.file_name.as_path()
    }
}

impl MemFsContext {
    #[allow(clippy::too_many_arguments)]
    fn new(
        case_insensitive: bool,
        max_file_nodes: u32,
        max_file_size: u32,
        root_sddl: Option<&str>,
        slowio_max_delay: u32,
        slowio_percent_delay: u32,
        slowio_rarefy_delay: u32,
        spawn_executor: bool,
    ) -> anyhow::Result<Self> {
        let mut state = MemFsState {
            nodes: HashMap::new(),
            by_name: BTreeMap::new(),
            next_node_id: 1,
            next_index_number: 1,
            volume_label: "MEMFS".encode_utf16().collect(),
            case_insensitive,
        };

        let root_security =
            read_sddl(root_sddl.unwrap_or("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"))?;

        let now = system_time_filetime();
        let root_id = state.next_node_id;
        state.next_node_id += 1;
        let root_index = state.next_index_number;
        state.next_index_number += 1;

        let root = MemFsNode {
            file_name: NtfsPathBuf::root(),
            file_info: FileInfo {
                file_attributes: FILE_ATTRIBUTE_DIRECTORY.0,
                reparse_tag: 0,
                allocation_size: 0,
                file_size: 0,
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
                index_number: root_index,
                hard_links: 0,
                ea_size: 0,
            },
            file_security: root_security,
            file_data: Vec::new(),
            reparse_data: Vec::new(),
            ea_map: std::collections::BTreeMap::new(),
            main_file_node: None,
            refcount: 1,
        };
        let canon = root.path().canonical_key(case_insensitive);
        state.nodes.insert(root_id, root);
        state.by_name.insert(canon, root_id);

        let executor = if spawn_executor {
            Some(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_time()
                    .build()
                    .map_err(|e| anyhow::anyhow!("failed to build tokio runtime: {e}"))?,
            )
        } else {
            None
        };

        Ok(Self {
            state: Mutex::new(state),
            case_insensitive,
            max_file_nodes,
            max_file_size,
            slowio: Slowio::new(slowio_max_delay, slowio_percent_delay, slowio_rarefy_delay),
            executor,
        })
    }
}

impl MemFsState {
    fn get_id(&self, path: &NtfsPath) -> Option<u64> {
        self.by_name
            .get(&path.canonical_key(self.case_insensitive))
            .copied()
    }

    fn node(&self, id: u64) -> &MemFsNode {
        self.nodes.get(&id).expect("invalid memfs handle")
    }

    fn node_mut(&mut self, id: u64) -> &mut MemFsNode {
        self.nodes.get_mut(&id).expect("invalid memfs handle")
    }

    fn lookup_parent(&self, path: &NtfsPath) -> Result<u64, FspError> {
        let (parent_slice, _) = path.parent_and_basename();
        let parent_buf = NtfsPathBuf::from_slice(parent_slice.as_slice())
            .ok_or(FspError::NTSTATUS(STATUS_OBJECT_PATH_NOT_FOUND.0))?;
        let id = self
            .by_name
            .get(&parent_buf.canonical_key(self.case_insensitive))
            .copied()
            .ok_or(FspError::NTSTATUS(STATUS_OBJECT_PATH_NOT_FOUND.0))?;
        let node = self.node(id);
        if node.file_info.file_attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
            return Err(FspError::NTSTATUS(STATUS_NOT_A_DIRECTORY.0));
        }
        Ok(id)
    }

    /// Look up a stream's main file node (the part before the colon).
    fn get_main_for(&self, path: &NtfsPath) -> Option<u64> {
        let main_slice = path.main_slice();
        if main_slice.as_slice() == path.as_slice() {
            return None;
        }
        let main_buf = NtfsPathBuf::from_slice(main_slice.as_slice())?;
        self.by_name
            .get(&main_buf.canonical_key(self.case_insensitive))
            .copied()
    }

    fn insert(&mut self, id: u64) {
        let key = self.node(id).path().canonical_key(self.case_insensitive);
        self.by_name.insert(key, id);
        let node = self.node_mut(id);
        node.refcount = node.refcount.saturating_add(1);
    }

    fn remove(&mut self, id: u64) -> bool {
        let key = match self.nodes.get(&id) {
            Some(n) => n.path().canonical_key(self.case_insensitive),
            None => return false,
        };
        if self.by_name.remove(&key).is_some() {
            self.dereference(id);
            true
        } else {
            false
        }
    }

    fn reference(&mut self, id: u64) {
        let node = self.node_mut(id);
        node.refcount = node.refcount.saturating_add(1);
    }

    fn dereference(&mut self, id: u64) {
        let node = self.node_mut(id);
        node.refcount = node.refcount.saturating_sub(1);
        if node.refcount == 0 {
            self.nodes.remove(&id);
        }
    }

    fn touch_parent(&mut self, path: &NtfsPath) {
        if path.is_root() {
            return;
        }
        let parent_id = match self.lookup_parent(path) {
            Ok(id) => id,
            Err(_) => return,
        };
        let now = system_time_filetime();
        let parent = self.node_mut(parent_id);
        parent.file_info.last_access_time = now;
        parent.file_info.last_write_time = now;
        parent.file_info.change_time = now;
    }

    fn has_child(&self, id: u64) -> bool {
        let case_insensitive = self.case_insensitive;
        let parent_path: NtfsPathBuf = self.node(id).path().to_owned();
        let parent = parent_path.as_path();
        let parent_canon = parent.canonical_key(case_insensitive);
        for (_, &other_id) in self
            .by_name
            .range::<NtfsPath, _>((Excluded(parent_canon.as_path()), Unbounded))
        {
            let other = self.node(other_id);
            let other_path = other.path();
            if !other_path.has_prefix(parent, case_insensitive) {
                break;
            }
            // Skip named streams when checking for directory children
            if other_path.stream_index().is_some() {
                continue;
            }
            let (other_parent_slice, _) = other_path.parent_and_basename();
            let Some(other_parent_buf) = NtfsPathBuf::from_slice(other_parent_slice.as_slice())
            else {
                continue;
            };
            if other_parent_buf.as_path().compare(parent, case_insensitive)
                == std::cmp::Ordering::Equal
            {
                return true;
            }
        }
        false
    }

    fn enumerate_streams(&self, id: u64) -> Vec<u64> {
        let case_insensitive = self.case_insensitive;
        let parent_path: NtfsPathBuf = self.node(id).path().to_owned();
        let parent = parent_path.as_path();
        let parent_canon = parent.canonical_key(case_insensitive);
        let parent_len = parent.len();
        let mut out = Vec::new();
        for (_, &other_id) in self
            .by_name
            .range::<NtfsPath, _>((Excluded(parent_canon.as_path()), Unbounded))
        {
            let other = self.node(other_id);
            let other_path = other.path();
            if !other_path.has_prefix(parent, case_insensitive) {
                break;
            }
            let other_slice = other_path.as_slice();
            if other_slice.len() <= parent_len || other_slice[parent_len] != COLON {
                break;
            }
            out.push(other_id);
        }
        out
    }

    fn enumerate_descendants(&self, id: u64) -> Vec<u64> {
        let case_insensitive = self.case_insensitive;
        let parent_path: NtfsPathBuf = self.node(id).path().to_owned();
        let parent = parent_path.as_path();
        let parent_canon = parent.canonical_key(case_insensitive);
        let mut out = Vec::new();
        for (_, &other_id) in self.by_name.range(parent_canon..) {
            let other = self.node(other_id);
            if !other.path().has_prefix(parent, case_insensitive) {
                break;
            }
            out.push(other_id);
        }
        out
    }
}

fn system_time_filetime() -> u64 {
    // Windows FILETIME: 100ns intervals since 1601-01-01.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let nanos_100 = now.as_secs() * 10_000_000 + (now.subsec_nanos() as u64) / 100;
    nanos_100 + 116_444_736_000_000_000u64
}

fn read_sddl(sddl: &str) -> anyhow::Result<Vec<u8>> {
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let mut size = 0u32;
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            Some(&mut size),
        )?;
    }
    if descriptor.0.is_null() {
        anyhow::bail!("SDDL parsing returned a null descriptor");
    }
    let len = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    let bytes = unsafe { std::slice::from_raw_parts(descriptor.0 as *const u8, len) }.to_vec();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    Ok(bytes)
}

fn get_file_info_for(node: &MemFsNode, main: Option<&MemFsNode>) -> FileInfo {
    match main {
        None => node.file_info.clone(),
        Some(main) => {
            let mut info = main.file_info.clone();
            info.file_attributes &= !FILE_ATTRIBUTE_DIRECTORY.0;
            info.allocation_size = node.file_info.allocation_size;
            info.file_size = node.file_info.file_size;
            info
        }
    }
}

fn set_normalized_name(file_info: &mut OpenFileInfo, file_name: &[u16]) {
    file_info.set_normalized_name(file_name, Some(BACKSLASH));
}

/// Apply every EA entry packed in `buffer` to `ea_map`, updating
/// `file_info.ea_size` accordingly. Mirrors the `FspFileSystemEnumerateEa`
/// loop in memfs.cpp.
fn apply_ea_buffer(
    ea_map: &mut std::collections::BTreeMap<Vec<u8>, MemFsEa>,
    file_info: &mut FileInfo,
    buffer: &[u8],
) -> winfsp::Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }
    for entry in ea::EaIter::new(buffer) {
        let entry = entry?;
        let delta = ea::apply_set(ea_map, &entry);
        file_info.ea_size = ((file_info.ea_size as i64) + delta).max(0) as u32;
    }
    Ok(())
}

impl FileSystemContext for MemFsContext {
    type FileContext = MemFsHandle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [std::ffi::c_void]>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let path = NtfsPath::from_u16cstr(file_name);
        let state = self.state.lock();

        let id = match state.get_id(path) {
            Some(id) => id,
            None => {
                drop(state);
                if let Some(sec) = reparse_point_resolver(file_name) {
                    return Ok(sec);
                }
                let state = self.state.lock();
                state.lookup_parent(path)?;
                return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0));
            }
        };

        let node = state.node(id);
        let (effective_node, attr_mask) = if let Some(main_id) = node.main_file_node {
            let main = state.node(main_id);
            (main, !FILE_ATTRIBUTE_DIRECTORY.0)
        } else {
            (node, !0u32)
        };

        let attributes = effective_node.file_info.file_attributes & attr_mask;
        let security_size = effective_node.file_security.len() as u64;

        if let Some(buffer) = security_descriptor {
            if (buffer.len() as u64) < security_size {
                return Ok(FileSecurity {
                    reparse: false,
                    sz_security_descriptor: security_size,
                    attributes,
                });
            }
            unsafe {
                let src = effective_node.file_security.as_ptr();
                let dst = buffer.as_mut_ptr() as *mut u8;
                std::ptr::copy_nonoverlapping(src, dst, effective_node.file_security.len());
            }
        }

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: security_size,
            attributes,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = NtfsPath::from_u16cstr(file_name);
        if path.len() >= MEMFS_MAX_PATH {
            return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_INVALID.0));
        }
        let mut state = self.state.lock();
        let id = match state.get_id(path) {
            Some(id) => id,
            None => {
                let _ = state.lookup_parent(path)?;
                return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0));
            }
        };

        // FILE_NO_EA_KNOWLEDGE: caller has declared they will ignore EAs.
        // Reject the open if the (main file) node has any NEED_EA-tagged
        // attribute. Matches the `MemfsFileNodeNeedEa` gate in memfs.cpp.
        if (create_options & FILE_NO_EA_KNOWLEDGE) != 0 {
            let needs = {
                let node = state.node(id);
                if node.main_file_node.is_some() {
                    false
                } else {
                    has_need_ea(&node.ea_map)
                }
            };
            if needs {
                return Err(FspError::NTSTATUS(STATUS_ACCESS_DENIED.0));
            }
        }
        state.reference(id);

        let node = state.node(id);
        let normalized_name = node.file_name.clone();
        let main_info = node
            .main_file_node
            .map(|mid| state.node(mid).file_info.clone());
        let file_info_value = match main_info {
            None => node.file_info.clone(),
            Some(main) => {
                let mut info = main;
                info.file_attributes &= !FILE_ATTRIBUTE_DIRECTORY.0;
                info.allocation_size = node.file_info.allocation_size;
                info.file_size = node.file_info.file_size;
                info
            }
        };

        *file_info.as_mut() = file_info_value;
        if self.case_insensitive {
            set_normalized_name(file_info, normalized_name.as_slice());
        }
        Ok(MemFsHandle(id))
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        file_attributes: u32,
        security_descriptor: Option<&[std::ffi::c_void]>,
        mut allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let requested_path = NtfsPath::from_u16cstr(file_name);
        if requested_path.len() >= MEMFS_MAX_PATH {
            return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_INVALID.0));
        }
        const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
        let is_directory = (create_options & FILE_DIRECTORY_FILE) != 0;
        if is_directory {
            allocation_size = 0;
        }

        let mut state = self.state.lock();

        if state.get_id(requested_path).is_some() {
            return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_COLLISION.0));
        }

        let parent_id = state.lookup_parent(requested_path)?;

        if state.by_name.len() as u32 >= self.max_file_nodes {
            return Err(FspError::NTSTATUS(STATUS_CANNOT_MAKE.0));
        }
        if allocation_size > self.max_file_size as u64 {
            return Err(FspError::NTSTATUS(STATUS_DISK_FULL.0));
        }

        // For case-insensitive mode, swap the parent component for the
        // parent node's stored on-disk name (case may differ from the input).
        let canonical_name: NtfsPathBuf = if self.case_insensitive {
            let parent_path = state.node(parent_id).file_name.clone();
            let (_, suffix) = requested_path.parent_and_basename();
            let combined = parent_path
                .join(suffix)
                .ok_or(FspError::NTSTATUS(STATUS_OBJECT_NAME_INVALID.0))?;
            if combined.len() >= MEMFS_MAX_PATH {
                return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_INVALID.0));
            }
            combined
        } else {
            NtfsPathBuf::from_u16cstr(file_name)
        };

        let attrs = if (file_attributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0 {
            file_attributes
        } else {
            file_attributes | FILE_ATTRIBUTE_ARCHIVE.0
        };

        let now = system_time_filetime();
        let id = state.next_node_id;
        state.next_node_id += 1;
        let index_number = state.next_index_number;
        state.next_index_number += 1;

        let main_file_node = state.get_main_for(canonical_name.as_path());

        let mut node = MemFsNode {
            file_name: canonical_name.clone(),
            file_info: FileInfo {
                file_attributes: attrs,
                reparse_tag: 0,
                allocation_size,
                file_size: 0,
                creation_time: now,
                last_access_time: now,
                last_write_time: now,
                change_time: now,
                index_number,
                hard_links: 0,
                ea_size: 0,
            },
            file_security: Vec::new(),
            file_data: Vec::new(),
            reparse_data: Vec::new(),
            ea_map: std::collections::BTreeMap::new(),
            main_file_node,
            refcount: 0,
        };

        if let Some(desc) = security_descriptor {
            let len = unsafe {
                GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR(desc.as_ptr().cast_mut()))
            } as usize;
            node.file_security =
                unsafe { std::slice::from_raw_parts(desc.as_ptr() as *const u8, len) }.to_vec();
        }

        if let Some(extra) = extra_buffer {
            if extra_buffer_is_reparse_point {
                node.reparse_data = extra.to_vec();
                node.file_info.file_attributes |= FILE_ATTRIBUTE_REPARSE_POINT.0;
                if extra.len() >= 4 {
                    let tag = u32::from_le_bytes([extra[0], extra[1], extra[2], extra[3]]);
                    node.file_info.reparse_tag = tag;
                }
            } else {
                apply_ea_buffer(&mut node.ea_map, &mut node.file_info, extra)?;
            }
        }

        if node.file_info.allocation_size > 0 {
            node.file_data = vec![0u8; node.file_info.allocation_size as usize];
        }

        state.nodes.insert(id, node);
        state.insert(id); // refcount becomes 1 (in-map)
        state.reference(id); // open handle bumps refcount to 2
        state.touch_parent(canonical_name.as_path());

        let node = state.node(id);
        let main_info = node
            .main_file_node
            .map(|mid| state.node(mid).file_info.clone());
        let info_value = match main_info {
            None => node.file_info.clone(),
            Some(mut info) => {
                info.file_attributes &= !FILE_ATTRIBUTE_DIRECTORY.0;
                info.allocation_size = node.file_info.allocation_size;
                info.file_size = node.file_info.file_size;
                info
            }
        };
        *file_info.as_mut() = info_value;
        if self.case_insensitive {
            let stored = node.file_name.clone();
            set_normalized_name(file_info, stored.as_slice());
        }

        Ok(MemFsHandle(id))
    }

    fn close(&self, context: Self::FileContext) {
        let mut state = self.state.lock();
        state.dereference(context.0);
    }

    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
        let mut state = self.state.lock();
        let id = context.0;
        let main_id = state.node(id).main_file_node.unwrap_or(id);

        if FspCleanupFlags::FspCleanupSetArchiveBit.is_flagged(flags) {
            let main = state.node_mut(main_id);
            if main.file_info.file_attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
                main.file_info.file_attributes |= FILE_ATTRIBUTE_ARCHIVE.0;
            }
        }

        if FspCleanupFlags::FspCleanupSetLastAccessTime.is_flagged(flags)
            || FspCleanupFlags::FspCleanupSetLastWriteTime.is_flagged(flags)
            || FspCleanupFlags::FspCleanupSetChangeTime.is_flagged(flags)
        {
            let now = system_time_filetime();
            let main = state.node_mut(main_id);
            if FspCleanupFlags::FspCleanupSetLastAccessTime.is_flagged(flags) {
                main.file_info.last_access_time = now;
            }
            if FspCleanupFlags::FspCleanupSetLastWriteTime.is_flagged(flags) {
                main.file_info.last_write_time = now;
            }
            if FspCleanupFlags::FspCleanupSetChangeTime.is_flagged(flags) {
                main.file_info.change_time = now;
            }
        }

        if FspCleanupFlags::FspCleanupSetAllocationSize.is_flagged(flags) {
            let target = {
                let n = state.node(id);
                let file_size = n.file_info.file_size;
                (file_size + ALLOCATION_UNIT - 1) / ALLOCATION_UNIT * ALLOCATION_UNIT
            };
            let _ = self.set_file_size_internal(&mut state, id, target, true);
        }

        if FspCleanupFlags::FspCleanupDelete.is_flagged(flags) && !state.has_child(id) {
            let streams = state.enumerate_streams(id);
            for stream_id in streams {
                state.remove(stream_id);
            }
            state.remove(id);
        }
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        let state = self.state.lock();
        let node = state.node(context.0);
        if offset >= node.file_info.file_size {
            return Err(FspError::NTSTATUS(STATUS_END_OF_FILE.0));
        }
        let end = (offset + buffer.len() as u64).min(node.file_info.file_size);
        let len = (end - offset) as usize;
        buffer[..len].copy_from_slice(&node.file_data[offset as usize..(offset as usize + len)]);
        Ok(len as u32)
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        let mut state = self.state.lock();
        let id = context.0;
        let mut start = offset;
        let end;
        if constrained_io {
            let size = state.node(id).file_info.file_size;
            if offset >= size {
                let main_id = state.node(id).main_file_node.unwrap_or(id);
                *file_info = get_file_info_for(state.node(id), state.nodes.get(&main_id));
                return Ok(0);
            }
            end = (offset + buffer.len() as u64).min(size);
        } else {
            if write_to_eof {
                start = state.node(id).file_info.file_size;
            }
            end = start + buffer.len() as u64;
            let current = state.node(id).file_info.file_size;
            if end > current {
                self.set_file_size_internal(&mut state, id, end, false)?;
            }
        }
        let len = (end - start) as usize;
        let node = state.node_mut(id);
        node.file_data[start as usize..start as usize + len].copy_from_slice(&buffer[..len]);

        let main_id = node.main_file_node.unwrap_or(id);
        let main = state.nodes.get(&main_id);
        *file_info = get_file_info_for(state.node(id), main);
        Ok(len as u32)
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let Some(handle) = context else { return Ok(()) };
        let state = self.state.lock();
        let node = state.node(handle.0);
        let main_id = node.main_file_node.unwrap_or(handle.0);
        *file_info = get_file_info_for(node, state.nodes.get(&main_id));
        Ok(())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let state = self.state.lock();
        let node = state.node(context.0);
        let main_id = node.main_file_node.unwrap_or(context.0);
        *file_info = get_file_info_for(node, state.nodes.get(&main_id));
        Ok(())
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock();
        let id = context.0;
        let target_id = state.node(id).main_file_node.unwrap_or(id);
        {
            let node = state.node_mut(target_id);
            if file_attributes != INVALID_FILE_ATTRIBUTES {
                node.file_info.file_attributes = file_attributes;
            }
            if creation_time != 0 {
                node.file_info.creation_time = creation_time;
            }
            if last_access_time != 0 {
                node.file_info.last_access_time = last_access_time;
            }
            if last_write_time != 0 {
                node.file_info.last_write_time = last_write_time;
            }
            if change_time != 0 {
                node.file_info.change_time = change_time;
            }
        }
        let node = state.node(id);
        let main_id = node.main_file_node.unwrap_or(id);
        *file_info = get_file_info_for(node, state.nodes.get(&main_id));
        Ok(())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock();
        self.set_file_size_internal(&mut state, context.0, new_size, set_allocation_size)?;
        let node = state.node(context.0);
        let main_id = node.main_file_node.unwrap_or(context.0);
        *file_info = get_file_info_for(node, state.nodes.get(&main_id));
        Ok(())
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        replace_file_attributes: bool,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock();
        let id = context.0;

        // Drop named streams whose only holders are the map+this overwrite.
        let stream_ids = state.enumerate_streams(id);
        for sid in &stream_ids {
            state.reference(*sid);
        }
        for sid in stream_ids {
            let rc = state.node(sid).refcount;
            if rc <= 2 {
                state.remove(sid);
            }
            state.dereference(sid);
        }

        // Clear the EA map (memfs.cpp's `MemfsFileNodeDeleteEaMap`) and then
        // apply whatever EAs were supplied as part of this overwrite.
        {
            let node = state.node_mut(id);
            node.ea_map.clear();
            node.file_info.ea_size = 0;
        }
        if let Some(buf) = extra_buffer
            && !buf.is_empty()
        {
            let node = state.node_mut(id);
            apply_ea_buffer(&mut node.ea_map, &mut node.file_info, buf)?;
        }

        self.set_file_size_internal(&mut state, id, allocation_size, true)?;

        let now = system_time_filetime();
        let node = state.node_mut(id);
        if replace_file_attributes {
            node.file_info.file_attributes = file_attributes | FILE_ATTRIBUTE_ARCHIVE.0;
        } else {
            node.file_info.file_attributes |= file_attributes | FILE_ATTRIBUTE_ARCHIVE.0;
        }
        node.file_info.file_size = 0;
        node.file_info.last_access_time = now;
        node.file_info.last_write_time = now;
        node.file_info.change_time = now;

        let node = state.node(id);
        let main_id = node.main_file_node.unwrap_or(id);
        *file_info = get_file_info_for(node, state.nodes.get(&main_id));
        Ok(())
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        if !delete_file {
            return Ok(());
        }
        let state = self.state.lock();
        if state.has_child(context.0) {
            return Err(FspError::NTSTATUS(STATUS_DIRECTORY_NOT_EMPTY.0));
        }
        Ok(())
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock();
        let id = context.0;
        let new_path_owned = NtfsPathBuf::from_u16cstr(new_file_name);
        if new_path_owned.len() >= MEMFS_MAX_PATH {
            return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_INVALID.0));
        }

        let existing = state.get_id(new_path_owned.as_path());
        if let Some(other_id) = existing {
            if other_id != id {
                if !replace_if_exists {
                    return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_COLLISION.0));
                }
                let other = state.node(other_id);
                if other.file_info.file_attributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0 {
                    return Err(FspError::NTSTATUS(STATUS_ACCESS_DENIED.0));
                }
            }
        }

        let descendants = state.enumerate_descendants(id);
        for did in &descendants {
            state.reference(*did);
        }

        let old_len = state.node(id).file_name.len();
        let new_slice = new_path_owned.as_slice().to_vec();
        let new_len = new_slice.len();
        for did in &descendants {
            if state.node(*did).file_name.len() - old_len + new_len >= MEMFS_MAX_PATH {
                for did2 in &descendants {
                    state.dereference(*did2);
                }
                return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_INVALID.0));
            }
        }

        if let Some(other_id) = existing {
            if other_id != id {
                state.reference(other_id);
                state.remove(other_id);
                state.dereference(other_id);
            }
        }

        for did in descendants.iter().copied() {
            let key = state.node(did).path().canonical_key(state.case_insensitive);
            state.by_name.remove(&key);
        }
        for did in descendants.iter().copied() {
            let mut new_full = new_slice.clone();
            new_full.extend_from_slice(&state.node(did).file_name.as_slice()[old_len..]);
            let updated = NtfsPathBuf::from_slice(&new_full)
                .ok_or(FspError::NTSTATUS(STATUS_OBJECT_NAME_INVALID.0))?;
            state.node_mut(did).file_name = updated;
        }
        for did in descendants.iter().copied() {
            let key = state.node(did).path().canonical_key(state.case_insensitive);
            state.by_name.insert(key, did);
        }
        for did in descendants {
            state.dereference(did);
        }

        Ok(())
    }

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: Option<&mut [std::ffi::c_void]>,
    ) -> winfsp::Result<u64> {
        let state = self.state.lock();
        let node = state.node(context.0);
        let effective = if let Some(main_id) = node.main_file_node {
            state.node(main_id)
        } else {
            node
        };
        let size = effective.file_security.len() as u64;
        if let Some(buffer) = security_descriptor {
            if (buffer.len() as u64) < size {
                return Err(FspError::NTSTATUS(STATUS_BUFFER_OVERFLOW.0));
            }
            unsafe {
                std::ptr::copy_nonoverlapping(
                    effective.file_security.as_ptr(),
                    buffer.as_mut_ptr() as *mut u8,
                    effective.file_security.len(),
                );
            }
        }
        Ok(size)
    }

    fn set_security(
        &self,
        context: &Self::FileContext,
        security_information: u32,
        modification_descriptor: ModificationDescriptor,
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock();
        let id = context.0;
        let target_id = state.node(id).main_file_node.unwrap_or(id);

        let mut new_descriptor: winfsp_sys::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            FspSetSecurityDescriptor(
                state.node(target_id).file_security.as_ptr() as *mut _,
                security_information,
                modification_descriptor.as_mut_ptr() as *mut _,
                &mut new_descriptor,
            )
        };
        if status != 0 {
            return Err(FspError::NTSTATUS(status));
        }
        let len =
            unsafe { GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR(new_descriptor)) } as usize;
        let bytes =
            unsafe { std::slice::from_raw_parts(new_descriptor as *const u8, len) }.to_vec();
        unsafe {
            FspDeleteSecurityDescriptor(
                new_descriptor as *mut _,
                Some(std::mem::transmute::<
                    unsafe extern "C" fn(
                        winfsp_sys::PSECURITY_DESCRIPTOR,
                        u32,
                        winfsp_sys::PSECURITY_DESCRIPTOR,
                        *mut winfsp_sys::PSECURITY_DESCRIPTOR,
                    ) -> i32,
                    unsafe extern "C" fn() -> i32,
                >(FspSetSecurityDescriptor)),
            );
        }
        state.node_mut(target_id).file_security = bytes;
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        let state = self.state.lock();
        let id = context.0;
        let case_insensitive = self.case_insensitive;
        let node_path: NtfsPathBuf = state.node(id).path().to_owned();
        let parent_info = if !node_path.is_root() {
            let parent_id = state.lookup_parent(node_path.as_path())?;
            Some(state.node(parent_id).file_info.clone())
        } else {
            None
        };

        let mut cursor = 0u32;
        let mut dir_info: DirInfo<255> = DirInfo::new();

        if let Some(parent_file_info) = &parent_info {
            let marker_is_dot = marker
                .inner_as_cstr()
                .map(|m| m.as_slice() == [b'.' as u16])
                .unwrap_or(false);
            let marker_is_none = marker.is_none();

            if marker_is_none {
                dir_info.reset();
                *dir_info.file_info_mut() = state.node(id).file_info.clone();
                dir_info.set_name_raw([b'.' as u16].as_slice())?;
                if !dir_info.append_to_buffer(buffer, &mut cursor) {
                    return Ok(cursor);
                }
            }
            if marker_is_none || marker_is_dot {
                dir_info.reset();
                *dir_info.file_info_mut() = parent_file_info.clone();
                dir_info.set_name_raw([b'.' as u16, b'.' as u16].as_slice())?;
                if !dir_info.append_to_buffer(buffer, &mut cursor) {
                    return Ok(cursor);
                }
            }
        }

        let marker_buf = marker.inner_as_cstr().map(|m| m.as_slice().to_vec());
        let post_dot = marker_buf
            .as_ref()
            .map(|m| m.as_slice() == [b'.' as u16])
            .unwrap_or(false);

        let start_after = if let Some(mb) = marker_buf.as_ref().filter(|_| !post_dot) {
            let combined = node_path
                .join(U16Str::from_slice(mb))
                .ok_or(FspError::NTSTATUS(STATUS_OBJECT_NAME_INVALID.0))?;
            Some(combined.canonical_key(case_insensitive))
        } else {
            None
        };
        let base_canon = node_path.canonical_key(case_insensitive);
        let range_start = start_after.as_ref().unwrap_or(&base_canon);

        for (_, &other_id) in state
            .by_name
            .range::<NtfsPath, _>((Excluded(range_start.as_path()), Unbounded))
        {
            let other = state.node(other_id);
            let other_path = other.path();
            if !other_path.has_prefix(node_path.as_path(), case_insensitive) {
                break;
            }
            if other_path.stream_index().is_some() {
                continue;
            }
            let (other_parent_slice, suffix) = other_path.parent_and_basename();
            let other_parent_buf = NtfsPathBuf::from_slice(other_parent_slice.as_slice())
                .ok_or(FspError::NTSTATUS(STATUS_OBJECT_NAME_INVALID.0))?;
            if other_parent_buf
                .as_path()
                .compare(node_path.as_path(), case_insensitive)
                != std::cmp::Ordering::Equal
            {
                continue;
            }

            dir_info.reset();
            *dir_info.file_info_mut() = other.file_info.clone();
            dir_info.set_name_raw(suffix.as_slice())?;
            if !dir_info.append_to_buffer(buffer, &mut cursor) {
                return Ok(cursor);
            }
        }

        DirInfo::<255>::finalize_buffer(buffer, &mut cursor);
        Ok(cursor)
    }

    fn get_dir_info_by_name(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        out_dir_info: &mut DirInfo,
    ) -> winfsp::Result<()> {
        let state = self.state.lock();
        let parent_path = state.node(context.0).file_name.clone();
        let full = parent_path
            .join(U16Str::from_slice(file_name.as_slice()))
            .ok_or(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0))?;
        if full.len() >= MEMFS_MAX_PATH {
            return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0));
        }

        let id = state
            .get_id(full.as_path())
            .ok_or(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0))?;
        let node = state.node(id);

        let (_, file_part) = node.path().parent_and_basename();
        out_dir_info.reset();
        *out_dir_info.file_info_mut() = node.file_info.clone();
        out_dir_info.set_name_raw(file_part.as_slice())?;
        Ok(())
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        let state = self.state.lock();
        let total = self.max_file_nodes as u64 * self.max_file_size as u64;
        let used = state.by_name.len() as u64 * self.max_file_size as u64;
        out_volume_info.total_size = total;
        out_volume_info.free_size = total.saturating_sub(used);
        let label_os: std::ffi::OsString =
            std::os::windows::prelude::OsStringExt::from_wide(&state.volume_label);
        out_volume_info.set_volume_label(&label_os);
        Ok(())
    }

    fn set_volume_label(
        &self,
        volume_label: &U16CStr,
        volume_info: &mut VolumeInfo,
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock();
        let new_label: Vec<u16> = volume_label.as_slice().iter().copied().take(31).collect();
        state.volume_label = new_label;
        drop(state);
        self.get_volume_info(volume_info)
    }

    fn get_reparse_point_by_name(
        &self,
        file_name: &U16CStr,
        _is_directory: bool,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        let state = self.state.lock();
        let path = NtfsPath::from_u16cstr(file_name);
        let id = state
            .get_id(path)
            .ok_or(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0))?;
        let node = state.node(id);
        if node.file_info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0 {
            return Err(FspError::NTSTATUS(STATUS_NOT_A_REPARSE_POINT.0));
        }
        if !buffer.is_empty() {
            if buffer.len() < node.reparse_data.len() {
                return Err(FspError::NTSTATUS(STATUS_BUFFER_TOO_SMALL.0));
            }
            buffer[..node.reparse_data.len()].copy_from_slice(&node.reparse_data);
        }
        Ok(node.reparse_data.len() as u64)
    }

    fn get_reparse_point(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        let state = self.state.lock();
        let id = context.0;
        let target_id = state.node(id).main_file_node.unwrap_or(id);
        let node = state.node(target_id);
        if node.file_info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0 {
            return Err(FspError::NTSTATUS(STATUS_NOT_A_REPARSE_POINT.0));
        }
        if buffer.len() < node.reparse_data.len() {
            return Err(FspError::NTSTATUS(STATUS_BUFFER_TOO_SMALL.0));
        }
        buffer[..node.reparse_data.len()].copy_from_slice(&node.reparse_data);
        Ok(node.reparse_data.len() as u64)
    }

    fn set_reparse_point(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        buffer: &[u8],
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock();
        let id = context.0;
        let target_id = state.node(id).main_file_node.unwrap_or(id);

        if state.has_child(target_id) {
            return Err(FspError::NTSTATUS(STATUS_DIRECTORY_NOT_EMPTY.0));
        }

        {
            let node = state.node(target_id);
            if !node.reparse_data.is_empty() {
                let status = unsafe {
                    FspFileSystemCanReplaceReparsePoint(
                        node.reparse_data.as_ptr() as *mut _,
                        node.reparse_data.len() as winfsp_sys::SIZE_T,
                        buffer.as_ptr() as *mut _,
                        buffer.len() as winfsp_sys::SIZE_T,
                    )
                };
                if status != 0 {
                    return Err(FspError::NTSTATUS(status));
                }
            }
        }

        let tag = if buffer.len() >= 4 {
            u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]])
        } else {
            0
        };
        let node = state.node_mut(target_id);
        node.file_info.file_attributes |= FILE_ATTRIBUTE_REPARSE_POINT.0;
        node.file_info.reparse_tag = tag;
        node.reparse_data = buffer.to_vec();
        Ok(())
    }

    fn delete_reparse_point(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        buffer: &[u8],
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock();
        let id = context.0;
        let target_id = state.node(id).main_file_node.unwrap_or(id);

        let node = state.node(target_id);
        if node.reparse_data.is_empty() {
            return Err(FspError::NTSTATUS(STATUS_NOT_A_REPARSE_POINT.0));
        }
        let status = unsafe {
            FspFileSystemCanReplaceReparsePoint(
                node.reparse_data.as_ptr() as *mut _,
                node.reparse_data.len() as winfsp_sys::SIZE_T,
                buffer.as_ptr() as *mut _,
                buffer.len() as winfsp_sys::SIZE_T,
            )
        };
        if status != 0 {
            return Err(FspError::NTSTATUS(status));
        }

        let node = state.node_mut(target_id);
        node.reparse_data.clear();
        node.file_info.file_attributes &= !FILE_ATTRIBUTE_REPARSE_POINT.0;
        node.file_info.reparse_tag = 0;
        Ok(())
    }

    fn get_stream_info(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        let state = self.state.lock();
        let id = context.0;
        let target_id = state.node(id).main_file_node.unwrap_or(id);
        let main = state.node(target_id);

        let mut cursor = 0u32;
        let mut info: StreamInfo<255> = StreamInfo::new();

        if main.file_info.file_attributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
            info.stream_size = main.file_info.file_size;
            info.stream_alloc_size = main.file_info.allocation_size;
            info.set_name_raw([].as_slice())?;
            if !info.append_to_buffer(buffer, &mut cursor) {
                return Ok(cursor);
            }
        }

        let stream_ids = state.enumerate_streams(target_id);
        for sid in stream_ids {
            let stream = state.node(sid);
            let stream_name = stream
                .path()
                .stream_name()
                .map(|s| s.as_slice().to_vec())
                .unwrap_or_default();
            info.reset();
            info.stream_size = stream.file_info.file_size;
            info.stream_alloc_size = stream.file_info.allocation_size;
            info.set_name_raw(stream_name.as_slice())?;
            if !info.append_to_buffer(buffer, &mut cursor) {
                return Ok(cursor);
            }
        }
        StreamInfo::<255>::finalize_buffer(buffer, &mut cursor);
        Ok(cursor)
    }

    fn get_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        let state = self.state.lock();
        let id = context.0;
        let target_id = state.node(id).main_file_node.unwrap_or(id);
        let node = state.node(target_id);

        let mut cursor = 0u32;
        for entry in node.ea_map.values() {
            if !ea::add_to_buffer(entry, buffer, &mut cursor) {
                return Ok(cursor);
            }
        }
        ea::finalize_buffer(buffer, &mut cursor);
        Ok(cursor)
    }

    fn set_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let mut state = self.state.lock();
        let id = context.0;
        let target_id = state.node(id).main_file_node.unwrap_or(id);
        {
            let node = state.node_mut(target_id);
            for entry in ea::EaIter::new(buffer) {
                let entry = entry?;
                let delta = ea::apply_set(&mut node.ea_map, &entry);
                node.file_info.ea_size = ((node.file_info.ea_size as i64) + delta).max(0) as u32;
            }
        }
        let node = state.node(id);
        let main_id = node.main_file_node.unwrap_or(id);
        *file_info = get_file_info_for(node, state.nodes.get(&main_id));
        Ok(())
    }

    fn control(
        &self,
        _context: &Self::FileContext,
        control_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> winfsp::Result<u32> {
        // ROT13 demo control: CTL_CODE(0x8000 + 'M', 'R', METHOD_BUFFERED, FILE_ANY_ACCESS).
        const MEMFS_ROT13_CODE: u32 = ctl_code(0x8000 + b'M' as u32, b'R' as u32, 0, 0);
        if control_code != MEMFS_ROT13_CODE {
            return Err(FspError::NTSTATUS(STATUS_INVALID_DEVICE_REQUEST.0));
        }
        if output.len() != input.len() {
            return Err(FspError::NTSTATUS(STATUS_INVALID_PARAMETER.0));
        }
        for (i, &b) in input.iter().enumerate() {
            output[i] = match b {
                b'A'..=b'M' | b'a'..=b'm' => b + 13,
                b'N'..=b'Z' | b'n'..=b'z' => b - 13,
                _ => b,
            };
        }
        Ok(input.len() as u32)
    }
}

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

impl MemFsContext {
    fn set_file_size_internal(
        &self,
        state: &mut MemFsState,
        id: u64,
        new_size: u64,
        set_allocation_size: bool,
    ) -> winfsp::Result<()> {
        let node = state.node_mut(id);
        if set_allocation_size {
            if node.file_info.allocation_size == new_size {
                return Ok(());
            }
            if new_size > self.max_file_size as u64 {
                return Err(FspError::NTSTATUS(STATUS_DISK_FULL.0));
            }
            node.file_data.resize(new_size as usize, 0);
            node.file_info.allocation_size = new_size;
            if node.file_info.file_size > new_size {
                node.file_info.file_size = new_size;
            }
        } else {
            if node.file_info.file_size == new_size {
                return Ok(());
            }
            if node.file_info.allocation_size < new_size {
                let alloc = (new_size + ALLOCATION_UNIT - 1) / ALLOCATION_UNIT * ALLOCATION_UNIT;
                if alloc > self.max_file_size as u64 {
                    return Err(FspError::NTSTATUS(STATUS_DISK_FULL.0));
                }
                node.file_data.resize(alloc as usize, 0);
                node.file_info.allocation_size = alloc;
            }
            if node.file_info.file_size < new_size {
                for b in &mut node.file_data[node.file_info.file_size as usize..new_size as usize] {
                    *b = 0;
                }
            }
            node.file_info.file_size = new_size;
        }
        Ok(())
    }
}

impl AsyncFileSystemContext for MemFsContext {
    async fn read_async(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        self.slowio.snooze().await;
        FileSystemContext::read(self, context, buffer, offset)
    }

    async fn write_async(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        self.slowio.snooze().await;
        FileSystemContext::write(
            self,
            context,
            buffer,
            offset,
            write_to_eof,
            constrained_io,
            file_info,
        )
    }

    async fn read_directory_async(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        self.slowio.snooze().await;
        FileSystemContext::read_directory(self, context, pattern, marker, buffer)
    }

    fn spawn_task(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        if let Some(rt) = self.executor.as_ref() {
            let _ = rt.spawn(future);
        }
    }
}
