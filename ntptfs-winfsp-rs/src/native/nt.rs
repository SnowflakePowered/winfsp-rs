use ntapi::ntioapi::FS_INFORMATION_CLASS;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{BOOLEAN, HANDLE, UNICODE_STRING};
use windows_sys::Win32::System::WindowsProgramming::{
    FILE_INFORMATION_CLASS, IO_STATUS_BLOCK, PIO_APC_ROUTINE,
};

#[link(name = "windows")]
#[allow(non_snake_case)]
extern "system" {
    pub fn NtReadFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: *mut c_void,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        Buffer: *mut c_void,
        Length: u32,
        ByteOffset: *mut u64,
        Key: *mut u32,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    pub fn NtWriteFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: *mut c_void,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        Buffer: *mut c_void,
        Length: u32,
        ByteOffset: *mut u64,
        Key: *mut u32,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    pub fn NtFlushBuffersFile(
        FileHandle: HANDLE,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    pub fn NtSetInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        FileInformation: *mut c_void,
        Length: u32,
        FileInformationClass: FILE_INFORMATION_CLASS,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    pub fn NtQueryInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        FileInformation: *mut c_void,
        Length: u32,
        FileInformationClass: FILE_INFORMATION_CLASS,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    pub fn NtQuerySecurityObject(
        Handle: HANDLE,
        SecurityInformation: u32,
        SecurityDescriptor: *mut c_void,
        Length: u32,
        LengthNeeded: *mut u32,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    pub fn NtQueryDirectoryFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PIO_APC_ROUTINE,
        ApcContext: *mut c_void,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        FileInformation: *mut c_void,
        Length: u32,
        FileInformationClass: FILE_INFORMATION_CLASS,
        ReturnSingleEntry: BOOLEAN,
        FileName: *mut UNICODE_STRING,
        RestartScan: BOOLEAN,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;

    pub fn NtQueryVolumeInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        FsInformation: *mut c_void,
        Length: u32,
        FsInformationClass: FS_INFORMATION_CLASS,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;
}

#[allow(non_snake_case)]
pub unsafe fn NtSetInformationFileGeneric<T>(
    FileHandle: HANDLE,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    FileInformation: *mut T,
    FileInformationClass: FILE_INFORMATION_CLASS,
) -> windows_sys::Win32::Foundation::NTSTATUS {
    unsafe {
        NtSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation.cast(),
            std::mem::size_of::<T>() as u32,
            FileInformationClass,
        )
    }
}
