use registry::{Data, Hive, Security};
use windows::core::HSTRING;
use windows::w;
use windows::Win32::Foundation::{ERROR_DELAY_LOAD_FAILED, ERROR_FILE_NOT_FOUND};
use windows::Win32::System::LibraryLoader::LoadLibraryW;

use crate::Result;

#[non_exhaustive]
#[derive(Copy, Clone)]
pub struct FspInit;

fn get_system_winfsp() -> Option<HSTRING> {
    let winfsp_install = Hive::LocalMachine
        .open("SOFTWARE\\WOW6432Node\\WinFsp", Security::Read)
        .ok()
        .and_then(|u| u.value("InstallDir").ok());
    let mut directory = match winfsp_install {
        Some(Data::String(string)) => string.to_os_string(),
        _ => return None,
    };

    directory.push("\\bin\\");

    if cfg!(target_arch = "x86_64") {
        directory.push("winfsp-x64.dll");
    } else if cfg!(target_arch = "i686") {
        directory.push("winfsp-x86.dll");
    } else {
        panic!("unsupported arch")
    }

    Some(HSTRING::from(directory))
}

fn get_local_winfsp() -> HSTRING {
    if cfg!(target_arch = "x86_64") {
        w!("winfsp-x64.dll").clone()
    } else if cfg!(target_arch = "i686") {
        w!("winfsp-x86.dll").clone()
    } else {
        panic!("unsupported arch")
    }
}

fn load_local_winfsp() -> Result<()> {
    unsafe {
        if LoadLibraryW(&get_local_winfsp()).is_err() {
            Err(ERROR_DELAY_LOAD_FAILED.into())
        } else {
            Ok(())
        }
    }
}

fn load_system_winfsp() -> Result<()> {
    unsafe {
        let system = get_system_winfsp().ok_or(ERROR_FILE_NOT_FOUND)?;
        if LoadLibraryW(&system).is_err() {
            Err(ERROR_DELAY_LOAD_FAILED.into())
        } else {
            Ok(())
        }
    }
}

/// Initialize WinFSP.
pub fn winfsp_init() -> Result<FspInit> {
    if  load_system_winfsp().is_err() {
        Err(ERROR_DELAY_LOAD_FAILED.into())
    } else {
        Ok(FspInit)
    }
}

/// Initialize WinFSP, but shut down if failed.
pub fn winfsp_init_or_die() -> FspInit {
    if winfsp_init().is_err() {
        std::process::exit(ERROR_DELAY_LOAD_FAILED.0 as i32)
    }
    FspInit
}
