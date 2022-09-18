use crate::fs::file::NtPassthroughFile;
use crate::native::lfs;
use std::ffi::OsStr;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ACCESS_FLAGS, FILE_ATTRIBUTE_NORMAL, FILE_FLAGS_AND_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::WindowsProgramming::{
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::Storage::FileSystem::FILE_CREATE;
use windows_sys::Win32::System::WindowsProgramming::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_NO_EA_KNOWLEDGE,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use winfsp::error::FspError;
use winfsp::filesystem::{FileSecurity, FileSystemContext, FSP_FSCTL_FILE_INFO, IoResult};
use winfsp::util::Win32SafeHandle;
#[repr(C)]
pub struct NtPassthroughContext {
    root_handle: Win32SafeHandle,
}

impl NtPassthroughContext {
    pub fn new(root_handle: Win32SafeHandle) -> Self {
        Self { root_handle }
    }
}

impl FileSystemContext for NtPassthroughContext {
    type FileContext = NtPassthroughFile;

    fn get_security_by_name<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        security_descriptor: PSECURITY_DESCRIPTOR,
        descriptor_len: Option<u64>,
    ) -> winfsp::Result<FileSecurity> {
        // todo: reparse

        let file_name = HSTRING::from(file_name.as_ref());
        let handle = lfs::lfs_open_file(
            *self.root_handle,
            PCWSTR(file_name.as_ptr()),
            READ_CONTROL.0,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT,
        )?;

        let attributes = lfs::lfs_query_file_attributes(*handle)?;

        // cache FileAttributes for Open
        unsafe {
            self.with_operation_response(|rsp| {
                rsp.Rsp.Create.Opened.FileInfo.FileAttributes = attributes;
            })
            .unwrap();
        }

        let needed_size = if let Some(descriptor_len) = descriptor_len {
            lfs::lfs_query_security(
                *handle,
                (OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION)
                    .0,
                security_descriptor,
                descriptor_len as u32,
            )?
        } else {
            0
        };

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: needed_size as u64,
            attributes,
        })
    }

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
    ) -> winfsp::Result<Self::FileContext> {
        let is_directory = create_options & FILE_DIRECTORY_FILE != 0;

        let mut maximum_access = if is_directory {
            granted_access
        } else {
            // MAXIMUM_ALLOWED
            FILE_ACCESS_FLAGS(0x02000000u32)
        };

        let mut create_options =
            create_options & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE | FILE_NO_EA_KNOWLEDGE);

        // WORKAROUND:
        // WOW64 appears to have a bug in some versions of the OS (seen on Win10 1909 and
        // Server 2012 R2), where NtQueryDirectoryFile may produce garbage if called on a
        // directory that has been opened without FILE_SYNCHRONOUS_IO_NONALERT.
        //
        // Garbage:
        // after a STATUS_PENDING has been waited, Iosb.Information reports bytes transferred
        // but the buffer does not get filled

        // Always open directories in a synchronous manner.

        if is_directory {
            maximum_access |= SYNCHRONIZE;
            create_options |= FILE_SYNCHRONOUS_IO_NONALERT
        }

        let mut allocation_size = if allocation_size != 0 {
            Some(allocation_size as i64)
        } else {
            None
        };

        let file_attributes = if file_attributes.0 == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            file_attributes
        };

        let file_name = HSTRING::from(file_name.as_ref());

        let result = lfs::lfs_create_file(
            *self.root_handle,
            PCWSTR(file_name.as_ptr()),
            maximum_access.0,
            security_descriptor,
            allocation_size.as_mut(),
            file_attributes.0,
            FILE_CREATE,
            FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
            // todo: ea
            &mut None,
        );

        let handle = match result {
            Ok(handle) => Ok(handle),
            Err(FspError::NTSTATUS(STATUS_INVALID_PARAMETER))
                if maximum_access.0 == 0x02000000u32 =>
            {
                lfs::lfs_create_file(
                    *self.root_handle,
                    PCWSTR(file_name.as_ptr()),
                    maximum_access.0,
                    security_descriptor,
                    allocation_size.as_mut(),
                    file_attributes.0,
                    FILE_CREATE,
                    FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT | create_options,
                    &mut None,
                )
            }
            Err(e) => Err(e),
        }?;

        todo!("update info");
        Ok(Self::FileContext::new(handle, 0, is_directory))
    }

    fn open<P: AsRef<OsStr>>(
        &self,
        file_name: P,
        create_options: u32,
        granted_access: FILE_ACCESS_FLAGS,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<Self::FileContext> {
        todo!()
    }

    fn close(&self, context: Self::FileContext) {
        todo!()
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<IoResult> {
        let bytes_read = lfs::lfs_read_file(context.handle(), buffer, offset)?;
        Ok(IoResult {
            bytes_transferred: bytes_read as u32,
            io_pending: false,
        })
    }

    fn write(
        &self,
        context: &Self::FileContext,
        mut buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FSP_FSCTL_FILE_INFO,
    ) -> winfsp::Result<IoResult> {
        if constrained_io {
            let mut fsize = lfs::lfs_fsize(context.handle())?;

            if offset >= fsize {
                return Ok(IoResult {
                    bytes_transferred: 0,
                    io_pending: false,
                });
            }

            if offset + buffer.len() as u64 > fsize {
                buffer = &buffer[0..(fsize as u64 - offset) as usize]
            }
        }

        let mut bytes_read = lfs::lfs_write_file(context.handle(), buffer, offset)?;
        todo!("het info internal");
        self.get_file_info_internal(context, file_info)?;
        return Ok(IoResult {
            bytes_transferred: bytes_read as u32,
            io_pending: false,
        });
    }
}
