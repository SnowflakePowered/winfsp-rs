use crate::error::Result;
use crate::filesystem::{DirInfo, DirMarker};
use crate::U16CStr;

use windows::core::PWSTR;
use windows::Win32::Foundation::STATUS_INVALID_DEVICE_REQUEST;
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::Win32::Storage::FileSystem::{FILE_ACCESS_FLAGS, FILE_FLAGS_AND_ATTRIBUTES};
use windows::Win32::System::WindowsProgramming::IO_STATUS_BLOCK;

use winfsp_sys::{
    FSP_FSCTL_FILE_INFO, FSP_FSCTL_TRANSACT_REQ, FSP_FSCTL_TRANSACT_RSP, FSP_FSCTL_VOLUME_INFO,
};

#[derive(Debug)]
pub struct FileSecurity {
    pub reparse: bool,
    pub sz_security_descriptor: u64,
    pub attributes: u32,
}

#[derive(Debug)]
pub struct IoResult {
    pub bytes_transferred: u32,
    pub io_pending: bool,
}

#[repr(C)]
#[derive(Default, Copy, Clone, Debug)]
pub struct FileInfo {
    pub file_attributes: u32,
    pub reparse_tag: u32,
    pub allocation_size: u64,
    pub file_size: u64,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub index_number: u64,
    pub hard_links: u32,
    pub ea_size: u32,
}

pub const MAX_PATH: usize = 260;

#[allow(unused_variables)]
pub trait FileSystemContext: Sized {
    type FileContext: Sized;
    fn get_security_by_name<P: AsRef<U16CStr>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<u32>,
    ) -> Result<FileSecurity>;

    fn open<P: AsRef<U16CStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<Self::FileContext>;

    fn close(&self, context: Self::FileContext);

    fn cleanup<P: AsRef<U16CStr>>(
        &self,
        context: &mut Self::FileContext,
        file_name: Option<P>,
        flags: u32,
    ) {
    }

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
    fn create<P: AsRef<U16CStr>>(
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
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
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

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> Result<u64> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn get_stream_info(&self, context: &Self::FileContext, buffer: &mut [u8]) -> Result<u32> {
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
        extra_buffer: Option<&[u8]>,
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

    fn read_directory<P: AsRef<U16CStr>>(
        &self,
        context: &mut Self::FileContext,
        pattern: Option<P>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn rename<P: AsRef<U16CStr>>(
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

    fn set_delete<P: AsRef<U16CStr>>(
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

    fn get_dir_info_by_name<P: AsRef<U16CStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        out_dir_info: &mut DirInfo,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn resolve_reparse_points<P: AsRef<U16CStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        index: u32,
        resolve_last_component: bool,
        io_status_block: &mut IO_STATUS_BLOCK,
        buffer: &mut [u8],
    ) -> Result<u32> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Get reparse point information by its name.
    ///
    /// Unlike WinFSP, you may assume that `buffer` is always valid and never null.
    fn get_reparse_point_by_name<P: AsRef<U16CStr>>(
        &self,
        file_name: P,
        is_directory: bool,
        buffer: &mut [u8],
    ) -> Result<u64> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn get_reparse_point<P: AsRef<U16CStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        buffer: &mut [u8],
    ) -> Result<u64> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn set_reparse_point<P: AsRef<U16CStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        buffer: &[u8],
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn delete_reparse_point<P: AsRef<U16CStr>>(
        &self,
        context: &Self::FileContext,
        file_name: P,
        buffer: &[u8],
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn get_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
    ) -> Result<u32> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    fn set_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Get the context response of the current FSP interface operation.
    ///
    /// ## Safety
    /// This function may be used only when servicing one of the FSP_FILE_SYSTEM_INTERFACE operations.
    /// The current operation context is stored in thread local storage.
    unsafe fn with_operation_response<T, F>(&self, f: F) -> Option<T>
    where
        F: FnOnce(&mut FSP_FSCTL_TRANSACT_RSP) -> T,
    {
        unsafe {
            if let Some(context) = winfsp_sys::FspFileSystemGetOperationContext().as_ref() {
                if let Some(response) = context.Response.as_mut() {
                    return Some(f(response));
                }
            }
        }
        None
    }

    /// Get the context request of the current FSP interface operation.
    ///
    /// ## Safety
    /// This function may be used only when servicing one of the FSP_FILE_SYSTEM_INTERFACE operations.
    /// The current operation context is stored in thread local storage.
    unsafe fn with_operation_request<T, F>(&self, f: F) -> Option<T>
    where
        F: FnOnce(&FSP_FSCTL_TRANSACT_REQ) -> T,
    {
        unsafe {
            if let Some(context) = winfsp_sys::FspFileSystemGetOperationContext().as_ref() {
                if let Some(request) = context.Request.as_ref() {
                    return Some(f(request));
                }
            }
        }
        None
    }
}
