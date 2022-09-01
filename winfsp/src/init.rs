use windows::w;
use windows::Win32::Foundation::ERROR_DELAY_LOAD_FAILED;
use windows::Win32::System::LibraryLoader::LoadLibraryW;

use crate::Result;

#[non_exhaustive]
pub struct FspInit;

/// Initialize WinFSP.
pub fn winfsp_init() -> Result<FspInit> {
    unsafe {
        if LoadLibraryW(w!("winfsp-x64.dll")).is_err() {
            Err(ERROR_DELAY_LOAD_FAILED.into())
        } else {
            Ok(FspInit)
        }
    }
}

/// Initialize WinFSP, but shut down if failed.
pub fn winfsp_init_or_die() -> FspInit {
    if winfsp_init().is_err() {
        std::process::exit(ERROR_DELAY_LOAD_FAILED.0 as i32)
    }
    FspInit
}
