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
fn read_install_dir(subkey: PCWSTR) -> Option<std::ffi::OsString> {
    use crate::constants::MAX_PATH;
    use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};

    let mut path = [0u16; MAX_PATH];
    let mut size = (path.len() * std::mem::size_of::<u16>()) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey,
            w!("InstallDir"),
            RRF_RT_REG_SZ,
            None,
            Some(path.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if status.is_err() {
        return None;
    }
    let path = U16CStr::from_slice(&path[0..(size as usize) / std::mem::size_of::<u16>()]).ok()?;
    Some(path.to_os_string())
}

#[cfg(feature = "system")]
fn get_system_winfsp() -> Option<windows::core::HSTRING> {
    // 32-bit installers land in WOW6432Node; ARM64 native installers
    // write directly under SOFTWARE.
    let mut directory = read_install_dir(w!("SOFTWARE\\WOW6432Node\\WinFsp"))
        .or_else(|| read_install_dir(w!("SOFTWARE\\WinFsp")))?;
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

/// Linkage environment for the active build target.
#[derive(Copy, Clone, PartialEq, Eq)]
enum LinkEnv {
    Msvc,
    GnuLlvm,
}

impl LinkEnv {
    fn detect(target_env: &str, target_abi: &str) -> Option<Self> {
        match (target_env, target_abi) {
            ("msvc", _) => Some(Self::Msvc),
            ("gnu", "llvm") => Some(Self::GnuLlvm),
            _ => None,
        }
    }
}

/// Build-time helper to enable `DELAYLOAD` linking to the system WinFSP.
///
/// This function should be called from `build.rs`. Reads target config
/// from cargo env vars so cross-compiled build scripts work correctly.
pub fn winfsp_link_delayload() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_abi = std::env::var("CARGO_CFG_TARGET_ABI").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_os != "windows" {
        panic!("unsupported triple");
    }
    let link_env = LinkEnv::detect(&target_env, &target_abi)
        .unwrap_or_else(|| panic!("unsupported triple"));

    let dll = match target_arch.as_str() {
        "x86_64" => "winfsp-x64.dll",
        "x86" => "winfsp-x86.dll",
        "aarch64" => "winfsp-a64.dll",
        _ => panic!("unsupported architecture"),
    };

    match link_env {
        LinkEnv::Msvc => {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:{dll}");
        }
        LinkEnv::GnuLlvm => {
            // LLVM-MinGW's libdelayimp.a isn't on rustc's link search
            // path by default; lld-link's --delayload lowering provides
            // the helper itself, and ld.lld in mingw mode requires the
            // GNU-style flag rather than MSVC's `/DELAYLOAD:`.
            println!("cargo:rustc-link-arg=-Wl,--delayload={dll}");
        }
    }
}
