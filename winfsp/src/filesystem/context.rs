use std::ffi::OsStr;

use windows::core::{Result, PCWSTR, PWSTR};
use windows::Win32::Foundation::STATUS_INVALID_DEVICE_REQUEST;
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{FILE_ACCESS_FLAGS, FILE_FLAGS_AND_ATTRIBUTES};

pub use winfsp_sys::{FSP_FSCTL_FILE_INFO, FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS};

pub struct FileSecurity {
    pub reparse: bool,
    pub sz_security_descriptor: u64,
    pub attributes: u32,
}

pub struct IoResult {
    pub bytes_transferred: u64,
    pub io_pending: bool,
}

#[allow(unused_variables)]
pub trait FileSystemContext: Sized {
    type FileContext: Sized;
    fn get_security_by_name<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> Result<FileSecurity>;

    fn open<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<Self::FileContext>;

    fn close(&self, context: Self::FileContext);

    fn cleanup<P: AsRef<OsStr>>(&self, context: &Self::FileContext, file_name: P, flags: u32) {}

    fn control(
        &self,
        context: &Self::FileContext,
        control_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u32> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    #[allow(clippy::too_many_arguments)]
    fn create<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: PSECURITY_DESCRIPTOR,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<Self::FileContext> {
        dbg!("create");
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn delete_reparse_point<P: AsRef<OsStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        buffer: &[u8],
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn flush(
        &self,
        context: &Self::FileContext,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn get_security<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> Result<u64> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn get_stream_info(&self, context: &Self::FileContext, buffer: &mut [u8]) -> Result<u64> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    // todo: wrap FSP_FSCTL_VOLUME_INFO
    fn get_volume_info(&self, out_volume_info: &mut FSP_FSCTL_VOLUME_INFO) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        replace_file_attributes: bool,
        allocation_size: u64,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<IoResult> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn read_directory<P: Into<PCWSTR>, M: Into<PWSTR>>(
        &self,
        context: &Self::FileContext,
        pattern: Option<P>,
        marker: Option<M>,
        buffer: &mut [u8],
    ) -> Result<u64> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn rename<P: AsRef<OsStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        new_file_name: P,
        replace_if_exists: bool,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    #[allow(clippy::too_many_arguments)]
    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn set_delete<P: AsRef<OsStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        delete_file: bool,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn set_security(
        &self,
        context: &Self::FileContext,
        security_information: u32,
        modification_descriptor: PSECURITY_DESCRIPTOR,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn set_volume_label<P: Into<PWSTR>>(
        &self,
        volume_label: P,
        volume_info: &mut FSP_FSCTL_VOLUME_INFO,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<IoResult> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    #[cfg(feature = "get_dir_info_by_name")]
    fn get_dir_info_by_name<P: AsRef<OsStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        dir_info: &mut FSP_FSCTL_DIR_INFO,
    ) -> Result<()> {
        // todo: wrap FSP_FSCTL_DIR_INFO
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    #[cfg(feature = "reparse_points")]
    fn get_reparse_point<P: AsRef<OsStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        buffer: &mut [u8],
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    #[cfg(feature = "reparse_points")]
    fn set_reparse_point<P: AsRef<OsStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        buffer: &[u8],
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }
    // todo: figure out extended attributes safely
}
