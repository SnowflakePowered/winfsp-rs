use crate::native::nt;
use ntapi::ntioapi::{
    FileFsAttributeInformation, FileFsSizeInformation, FILE_FS_ATTRIBUTE_INFORMATION,
    FILE_FS_SIZE_INFORMATION,
};
use std::ffi::c_void;
use std::mem::MaybeUninit;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows_sys::Win32::System::WindowsProgramming::IO_STATUS_BLOCK;
use winfsp::filesystem::MAX_PATH;
use winfsp::util::VariableSizedBox;

pub fn get_attr(handle: HANDLE) -> winfsp::Result<VariableSizedBox<FILE_FS_ATTRIBUTE_INFORMATION>> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut info = VariableSizedBox::<FILE_FS_ATTRIBUTE_INFORMATION>::new(
        MAX_PATH * std::mem::size_of::<u16>(),
    );

    let result = unsafe {
        NTSTATUS(nt::NtQueryVolumeInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            info.as_mut_ptr() as *mut _,
            info.len() as u32,
            FileFsAttributeInformation,
        ))
    };

    if result.is_ok() {
        Ok(info)
    } else {
        Err(result.into())
    }
}

pub fn get_size(handle: HANDLE) -> winfsp::Result<FILE_FS_SIZE_INFORMATION> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut info: FILE_FS_SIZE_INFORMATION = unsafe { std::mem::zeroed() };

    let result = unsafe {
        NTSTATUS(nt::NtQueryVolumeInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            (&mut info) as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_FS_SIZE_INFORMATION>() as u32,
            FileFsSizeInformation,
        ))
    };

    if result.is_ok() {
        Ok(info)
    } else {
        Err(result.into())
    }
}
