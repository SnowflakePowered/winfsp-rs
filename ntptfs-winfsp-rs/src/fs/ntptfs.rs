use crate::fs::context::NtPassthroughContext;
use std::io::ErrorKind;

use std::path::Path;
use windows::core::HSTRING;
use windows::w;
use winfsp::filesystem::{FileSystemHost, FSP_FSCTL_VOLUME_PARAMS};

pub struct NtPassthroughFilesystem {
    pub fs: FileSystemHost,
}

impl NtPassthroughFilesystem {
    pub fn create<P: AsRef<Path>>(path: P, volume_prefix: &str) -> anyhow::Result<Self> {
        let metadata = std::fs::metadata(&path)?;
        if !metadata.is_dir() {
            return Err(std::io::Error::new(ErrorKind::NotADirectory, "not a directory").into());
        }
        let canonical_path = std::fs::canonicalize(&path)?;

        let mut volume_params = FSP_FSCTL_VOLUME_PARAMS {
            // SectorSize: 4096,
            // SectorsPerAllocationUnit: 1,
            // VolumeCreationTime: metadata.creation_time(),
            // VolumeSerialNumber: 0,
            // FileInfoTimeout: 1000,
            ..Default::default()
        };

        let prefix = HSTRING::from(volume_prefix);
        let fs_name = w!("ntptfs");

        volume_params.Prefix[..std::cmp::min(prefix.len(), 192)]
            .copy_from_slice(&prefix.as_wide()[..std::cmp::min(prefix.len(), 192)]);

        volume_params.FileSystemName[..std::cmp::min(fs_name.len(), 192)]
            .copy_from_slice(&fs_name.as_wide()[..std::cmp::min(fs_name.len(), 192)]);

        let context =
            NtPassthroughContext::new_with_volume_params(canonical_path, &mut volume_params)?;

        dbg!(HSTRING::from_wide(&volume_params.FileSystemName), fs_name);

        unsafe {
            Ok(NtPassthroughFilesystem {
                fs: FileSystemHost::new(volume_params, context)?,
            })
        }
    }
}
