#![deny(unsafe_op_in_unsafe_fn)]

mod ea;
mod main_args;
mod memfs;
mod path;
mod service;
mod slowio;

use clap::Parser;
use windows::Win32::Foundation::STATUS_NONCONTINUABLE_EXCEPTION;
use winfsp::service::FileSystemServiceBuilder;
use winfsp::winfsp_init_or_die;

fn main() {
    let init = winfsp_init_or_die();
    let mut fsp = FileSystemServiceBuilder::new()
        .with_start(|| {
            let args = main_args::Args::parse();
            service::svc_start(args).map_err(|_| STATUS_NONCONTINUABLE_EXCEPTION.into())
        })
        .with_stop(|fs| {
            service::svc_stop(fs);
            Ok(())
        })
        .build("memfs-winfsp-rs", init)
        .expect("failed to build fsp service");

    fsp.start().expect("failed to start fsp service");
    let _ = fsp.join();
}
