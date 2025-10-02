#![deny(unsafe_op_in_unsafe_fn)]

pub mod fs;
mod native;
mod service;

use clap::Parser;
use std::path::PathBuf;
use windows::Win32::Foundation::STATUS_NONCONTINUABLE_EXCEPTION;
use winfsp::service::FileSystemServiceBuilder;
use winfsp::winfsp_init_or_die;

/// MainArgs
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None,)]
pub struct Args {
    /// -1: enable all debug logs
    #[clap(short = 'd', default_value = "0")]
    flags: i32,

    /// file path
    #[clap(short = 'D', long)]
    logfile: Option<PathBuf>,

    #[clap(short = 'u', long)]
    volume_prefix: Option<String>,

    #[clap(short = 'p', long)]
    directory: PathBuf,

    #[clap(short = 'm', long)]
    mountpoint: PathBuf,
}

fn main() {
    let init = winfsp_init_or_die();
    let fsp = FileSystemServiceBuilder::new()
        .with_start(|| {
            let args = Args::parse();
            Ok(service::svc_start(args).map_err(|_e| STATUS_NONCONTINUABLE_EXCEPTION)?)
        })
        .with_stop(|f| {
            service::svc_stop(f);
            Ok(())
        })
        .build("ntptfs-winfsp-rs", init)
        .expect("failed to build fsp");

    let _ = fsp.start().join();
}
