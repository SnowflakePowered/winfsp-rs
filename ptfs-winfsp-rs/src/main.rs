#![feature(io_error_more)]
#![deny(unsafe_op_in_unsafe_fn)]

mod fs;
mod service;

use clap::Parser;
use std::path::PathBuf;
use windows::w;
use windows::Win32::Foundation::{
    EXCEPTION_NONCONTINUABLE_EXCEPTION, STATUS_SUCCESS,
};
use winfsp::service::{FileSystemService, fs_test, FSP_SERVICE, FspServiceRunEx};
use winfsp::winfsp_init_or_die;

unsafe extern "C" fn _svc_start(
    service: *mut FSP_SERVICE,
    _argc: u32,
    _argv: *mut *mut u16,
) -> i32 {
    let args = Args::parse();

    unsafe {
        match service::svc_start(FileSystemService::from_raw_unchecked(service), args) {
            Err(_e) => EXCEPTION_NONCONTINUABLE_EXCEPTION.0,
            Ok(_) => STATUS_SUCCESS.0,
        }
    }
}

unsafe extern "C" fn _svc_stop(service: *mut FSP_SERVICE) -> i32 {
    unsafe { service::svc_stop(FileSystemService::from_raw_unchecked(service)).0 }
}

/// MainArgs
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None,)]
pub struct Args {
    /// -1: enable all debug logs
    #[clap(short = 'd', default_value = "0")]
    flags: u32,

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
    winfsp_init_or_die();

    fs_test(|fss| {
        let args = Args::parse();
        service::svc_start(fss, args)?;
        Ok::<(), anyhow::Error>(())
    }, |fss| {
        service::svc_stop(fss).0
    });
    // unsafe {
    //     FspServiceRunEx(
    //         w!("ptfs-winfsp-rs").as_ptr().cast_mut(),
    //         Some(_svc_start),
    //         Some(_svc_stop),
    //         None,
    //         std::ptr::null_mut(),
    //     );
    // }
}
