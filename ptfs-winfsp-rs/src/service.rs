use crate::fs::Ptfs;
use crate::Args;

#[inline]
pub fn svc_start(args: Args) -> anyhow::Result<Ptfs> {
    let mut ptfs = Ptfs::create(
        &args.directory,
        &args.volume_prefix.unwrap_or(String::from("")),
    )?;

    ptfs.fs.mount(args.mountpoint.as_os_str())?;
    ptfs.fs.start()?;
    Ok(ptfs)
}

#[inline]
pub fn svc_stop(fs: Option<&mut Ptfs>) {
    if let Some(f) = fs {
        f.fs.stop();
    }
}
