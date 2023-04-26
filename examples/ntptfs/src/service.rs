use crate::fs::ntptfs::NtPassthroughFilesystem;
use crate::Args;

#[inline]
pub fn svc_start(args: Args) -> anyhow::Result<NtPassthroughFilesystem> {
    let mut ntptfs = NtPassthroughFilesystem::create(
        &args.directory,
        &args.volume_prefix.unwrap_or_else(|| String::from("")),
    )?;

    ntptfs.fs.mount(args.mountpoint.as_os_str())?;
    ntptfs.fs.start()?;
    Ok(ntptfs)
}

#[inline]
pub fn svc_stop(fs: Option<&mut NtPassthroughFilesystem>) {
    if let Some(f) = fs {
        f.fs.stop();
    }
}
