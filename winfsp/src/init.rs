#[cfg(feature = "system")]
use registry::{Data, Hive, Security};
use windows::core::HSTRING;
use windows::w;
#[allow(unused_imports)]
use windows::Win32::Foundation::{ERROR_DELAY_LOAD_FAILED, ERROR_FILE_NOT_FOUND};
use windows::Win32::System::LibraryLoader::LoadLibraryW;

use crate::Result;

/// WinFSP initialization token.
///
/// WinFSP must be initialized with [`winfsp_init`](crate::winfsp_init) or [`winfsp_init_or_die`](crate::winfsp_init_or_die)
/// by the host process, which yields this token to be used with [`FileSystemServiceBuilder`](crate::service::FileSystemServiceBuilder).
#[non_exhaustive]
#[derive(Copy, Clone)]
pub struct FspInit;

#[cfg(feature = "system")]
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
    #[cfg(feature = "system")]
    unsafe {
        let system = get_system_winfsp().ok_or(ERROR_FILE_NOT_FOUND)?;
        if LoadLibraryW(&system).is_err() {
            Err(ERROR_DELAY_LOAD_FAILED.into())
        } else {
            Ok(())
        }
    }

    #[cfg(not(feature = "system"))]
    Err(ERROR_DELAY_LOAD_FAILED.into())
}

/// Initialize WinFSP.
pub fn winfsp_init() -> Result<FspInit> {
    if load_local_winfsp().is_err() && load_system_winfsp().is_err() {
        Err(ERROR_DELAY_LOAD_FAILED.into())
    } else {
        Ok(FspInit)
    }
}

/// Initialize WinFSP, shutting down the executing process on failure.
pub fn winfsp_init_or_die() -> FspInit {
    if winfsp_init().is_err() {
        std::process::exit(ERROR_DELAY_LOAD_FAILED.0 as i32)
    }
    FspInit
}

/// Build-time helper to enable `DELAYLOAD` linking to the system WinFSP.
///
/// This function should be called from `build.rs`.
pub fn winfsp_link_delayload() {
    if cfg!(target(os = "windows", arch = "x86_64", env = "msvc")) {
        println!("cargo:rustc-link-lib=dylib=delayimp");
        println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
    } else if cfg!(target(os = "windows", arch = "i686", env = "msvc")) {
        println!("cargo:rustc-link-lib=dylib=delayimp");
        println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x86.dll");
    } else {
        panic!("unsupported triple")
    }
}
