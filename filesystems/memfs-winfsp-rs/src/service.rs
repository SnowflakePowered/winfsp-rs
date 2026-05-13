use crate::main_args::Args;
use crate::memfs::{MemFs, MemFsFlags, MemFsParams};

pub fn svc_start(args: Args) -> anyhow::Result<MemFs> {
    let mut flags = MemFsFlags::empty();
    if args.case_insensitive {
        flags |= MemFsFlags::CASE_INSENSITIVE;
    }
    if args.flush_and_purge_on_cleanup {
        flags |= MemFsFlags::FLUSH_AND_PURGE_ON_CLEANUP;
    }

    let params = MemFsParams {
        flags,
        file_info_timeout: args.file_info_timeout,
        max_file_nodes: args.max_file_nodes,
        max_file_size: args.max_file_size,
        file_system_name: args.file_system_name.clone(),
        volume_prefix: args.volume_prefix.clone(),
        root_sddl: args.root_sddl.clone(),
        slowio_max_delay: args.slowio_max_delay,
        slowio_percent_delay: args.slowio_percent_delay,
        slowio_rarefy_delay: args.slowio_rarefy_delay,
    };

    let mut memfs = MemFs::create(params)?;
    if let Some(mount) = args.mountpoint.as_deref() {
        if !(mount == "*" || mount.is_empty()) {
            memfs.fs.mount(mount)?;
        }
    }
    memfs.fs.start()?;
    Ok(memfs)
}

pub fn svc_stop(fs: Option<&mut MemFs>) {
    if let Some(memfs) = fs {
        memfs.fs.stop();
    }
}
