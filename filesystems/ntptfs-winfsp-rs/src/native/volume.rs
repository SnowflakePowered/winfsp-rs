use std::ffi::c_void;
use std::mem::MaybeUninit;
use windows::Wdk::Storage::FileSystem::{
    FILE_FS_ATTRIBUTE_INFORMATION, FileFsAttributeInformation, FileFsSizeInformation,
    NtQueryVolumeInformationFile,
};
use windows::Wdk::System::SystemServices::FILE_FS_SIZE_INFORMATION;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use winfsp::constants::MAX_PATH;
use winfsp::util::VariableSizedBox;

pub fn get_attr(handle: HANDLE) -> winfsp::Result<VariableSizedBox<FILE_FS_ATTRIBUTE_INFORMATION>> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut info = VariableSizedBox::<FILE_FS_ATTRIBUTE_INFORMATION>::new(
        MAX_PATH * std::mem::size_of::<u16>(),
    );

    unsafe {
        NtQueryVolumeInformationFile(
            handle,
            iosb.as_mut_ptr(),
            info.as_mut_ptr() as *mut _,
            info.len() as u32,
            FileFsAttributeInformation,
        )
        .ok()?;
    }
    Ok(info)
}

pub fn get_size(handle: HANDLE) -> winfsp::Result<FILE_FS_SIZE_INFORMATION> {
    let mut iosb: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
    let mut info: FILE_FS_SIZE_INFORMATION = unsafe { std::mem::zeroed() };

    unsafe {
        NtQueryVolumeInformationFile(
            handle,
            iosb.as_mut_ptr(),
            (&mut info) as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_FS_SIZE_INFORMATION>() as u32,
            FileFsSizeInformation,
        )
        .ok()?;
    };

    Ok(info)
}
