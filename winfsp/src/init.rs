#[cfg(feature = "system")]
use widestring::U16CStr;
#[allow(unused_imports)]
use windows::Win32::Foundation::{ERROR_DELAY_LOAD_FAILED, ERROR_FILE_NOT_FOUND};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::core::PCWSTR;
use windows::core::w;

use crate::Result;

/// WinFSP initialization token.
///
/// WinFSP must be initialized with [`winfsp_init`](crate::winfsp_init) or [`winfsp_init_or_die`](crate::winfsp_init_or_die)
/// by the host process, which yields this token to be used with [`FileSystemServiceBuilder`](crate::service::FileSystemServiceBuilder).
#[non_exhaustive]
#[derive(Copy, Clone)]
pub struct FspInit;

#[cfg(feature = "system")]
fn get_system_winfsp() -> Option<windows::core::HSTRING> {
    use crate::constants::MAX_PATH;
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};

    let mut path = [0u16; MAX_PATH];
    let mut size = (path.len() * std::mem::size_of::<u16>()) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\WOW6432Node\\WinFsp"),
            w!("InstallDir"),
            RRF_RT_REG_SZ,
            None,
            Some(path.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status.is_err() {
        return None;
    };

    let Ok(path) = U16CStr::from_slice(&path[0..(size as usize) / std::mem::size_of::<u16>()])
    else {
        return None;
    };

    let mut directory = path.to_os_string();
    directory.push("\\bin\\");

    if cfg!(target_arch = "x86_64") {
        directory.push("winfsp-x64.dll");
    } else if cfg!(target_arch = "x86") {
        directory.push("winfsp-x86.dll");
    } else if cfg!(target_arch = "aarch64") {
        directory.push("winfsp-a64.dll");
    } else {
        panic!("unsupported arch")
    }

    Some(windows::core::HSTRING::from(directory))
}

fn get_local_winfsp() -> PCWSTR {
    if cfg!(target_arch = "x86_64") {
        w!("winfsp-x64.dll")
    } else if cfg!(target_arch = "x86") {
        w!("winfsp-x86.dll")
    } else if cfg!(target_arch = "aarch64") {
        w!("winfsp-a64.dll")
    } else {
        panic!("unsupported arch")
    }
}

fn load_local_winfsp() -> Result<()> {
    unsafe {
        if LoadLibraryW(get_local_winfsp()).is_err() {
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
    if cfg!(all(target_os = "windows", target_env = "msvc")) {
        if cfg!(target_arch = "x86_64") {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
        } else if cfg!(target_arch = "x86") {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x86.dll");
        } else if cfg!(target_arch = "aarch64") {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-a64.dll");
        } else {
            panic!("unsupported architecture")
        }
    } else {
        panic!("unsupported triple")
    }
}
