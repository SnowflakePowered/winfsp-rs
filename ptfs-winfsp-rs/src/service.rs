use crate::fs::Ptfs;
use crate::Args;
use winfsp::service::FileSystemService;

use windows::Win32::Foundation::{EXCEPTION_NONCONTINUABLE_EXCEPTION, NTSTATUS, STATUS_SUCCESS};

#[inline]
pub fn svc_start(mut service: FileSystemService<Ptfs>, args: Args) -> anyhow::Result<()> {
    let mut ptfs = Ptfs::create(
        &args.directory,
        &args.volume_prefix.unwrap_or(String::from("")),
    )?;

    ptfs.fs.mount(args.mountpoint.as_os_str())?;
    ptfs.fs.start()?;
    service.set_context(ptfs);
    Ok(())
}

#[inline]
pub fn svc_stop(mut service: FileSystemService<Ptfs>) -> NTSTATUS {
    let context = service.get_context();
    context
        .map(|f| {
            f.fs.stop();
        })
        .map_or_else(|| EXCEPTION_NONCONTINUABLE_EXCEPTION, |_| STATUS_SUCCESS)
}
