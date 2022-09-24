use crate::fs::context::NtPassthroughContext;
use std::io::ErrorKind;

use std::path::Path;

use winfsp::host::{
    DebugMode, FileContextMode, FileSystemHost, FileSystemParams, VolumeParams,
};

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

        let mut volume_params = VolumeParams::new(FileContextMode::Descriptor);
        volume_params
            .prefix(volume_prefix)
            .filesystem_name("ntptfs");

        let context =
            NtPassthroughContext::new_with_volume_params(canonical_path, &mut volume_params)?;

        Ok(NtPassthroughFilesystem {
            fs: FileSystemHost::new_with_options(
                FileSystemParams::default_options_debug(volume_params, DebugMode::all()),
                context,
            )?,
        })
    }
}
