use crate::U16CStr;
use crate::error::Result;
use crate::filesystem::{DirInfo, DirMarker, FileInfo, OpenFileInfo, VolumeInfo};
use std::ffi::c_void;
use windows::Win32::Foundation::STATUS_INVALID_DEVICE_REQUEST;

use winfsp_sys::{
    FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES, FSP_FSCTL_TRANSACT_REQ, FSP_FSCTL_TRANSACT_RSP,
    PSECURITY_DESCRIPTOR,
};

/// A security descriptor pointer used to update an existing security descriptor.
/// The internal layout of this struct should not be relied on.
#[repr(transparent)]
pub struct ModificationDescriptor(pub(crate) PSECURITY_DESCRIPTOR);

impl ModificationDescriptor {
    /// Returns a `PSECURITY_DESCRIPTOR` pointer to the descriptor.
    pub fn as_mut_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }
}

#[derive(Debug)]
/// The return value of a request to [`FileSystemContext::get_security_by_name`](crate::filesystem::FileSystemContext::get_security_by_name).
pub struct FileSecurity {
    /// When a file name containing reparse points anywhere but the final path component is encountered,
    /// this should be true.
    pub reparse: bool,

    /// The size of the security descriptor needed to hold security information about the file.
    pub sz_security_descriptor: u64,

    /// The file attributes of the file.
    pub attributes: u32,
}

#[allow(unused_variables)]
/// The core trait that implements file system operations for a WinFSP file system.
///
/// If an implementor of this trait panics in any of the methods,
/// the caller will receive `STATUS_NONCONTINUABLE_EXCEPTION` (0xC0000025).
///
/// Any non-implemented optional methods will return `STATUS_INVALID_DEVICE_REQUEST` (0xC0000010).
///
/// Notice that once created, `FileContext` is only accessible through a shared, immutable
/// reference. This may be an obstacle when the `FileContext` needs to be mutated. This is because the filesystem
/// driver can call any of the trait methods on any thread, and `&mut` aliasing rules can not be guaranteed.
/// Instead, interior mutability wrappers should be used whenever a `FileContext` field needs to be mutated.
/// As an example, [`DirBuffer`](crate::filesystem::DirBuffer) implements interior mutability for the filesystem
/// driver managed directory buffer.
pub trait FileSystemContext: Sized {
    /// The user context that represents an open handle in the file system.
    ///
    /// The semantics of `FileContext` vary depending on the volume parameters
    /// used to mount the file system. See [`FileContextMode`](crate::host::FileContextMode)
    /// for more information.
    type FileContext: Sized;

    /// Get security information and attributes for a file or directory by its file name.
    ///
    /// If the file system supports reparse points, `reparse_point_resolver` should be
    /// called with the input file_name. If a reparse point is found at any point
    /// in the path, the result can be immediately returned like so the following.
    ///
    /// ```rust,ignore
    /// if let Some(security) = resolve_reparse_points(file_name.as_ref()) {
    ///    Ok(security)
    /// }
    /// ```
    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [c_void]>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> Result<FileSecurity>;

    /// Opens a file or a directory.
    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext>;

    /// Close a file or directory handle.
    fn close(&self, context: Self::FileContext);

    #[allow(clippy::too_many_arguments)]
    /// Create a new file or directory.
    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: FILE_ACCESS_RIGHTS,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        security_descriptor: Option<&[c_void]>,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> Result<Self::FileContext> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Clean up a file.
    fn cleanup(&self, context: &Self::FileContext, file_name: Option<&U16CStr>, flags: u32) {}

    /// Flush a file or volume.
    ///
    /// If `context` is `None`, the request is to flush the entire volume.
    fn flush(&self, context: Option<&Self::FileContext>, file_info: &mut FileInfo) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Get file or directory information.
    fn get_file_info(&self, context: &Self::FileContext, file_info: &mut FileInfo) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Get file or directory security descriptor.
    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: Option<&mut [c_void]>,
    ) -> Result<u64> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Set file or directory security descriptor.
    fn set_security(
        &self,
        context: &Self::FileContext,
        security_information: u32,
        modification_descriptor: ModificationDescriptor,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Overwrite a file.
    fn overwrite(
        &self,
        context: &Self::FileContext,
        file_attributes: FILE_FLAGS_AND_ATTRIBUTES,
        replace_file_attributes: bool,
        allocation_size: u64,
        extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Read directory entries from a directory handle.
    fn read_directory(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> Result<u32> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Renames a file or directory.
    fn rename(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        replace_if_exists: bool,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Set file or directory basic information.
    #[allow(clippy::too_many_arguments)]
    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        file_attributes: u32,
        creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Set the file delete flag.
    ///
    /// ## Safety
    /// The file should **never** be deleted in this function. Instead,
    /// set a flag to indicate that the file is to be deleted later by
    /// [`FileSystemContext::cleanup`](crate::filesystem::FileSystemContext::cleanup).
    fn set_delete(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        delete_file: bool,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Set the file or allocation size.
    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Read from a file. Return the number of bytes read,
    fn read(&self, context: &Self::FileContext, buffer: &mut [u8], offset: u64) -> Result<u32> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Write to a file. Return the number of bytes written.
    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> Result<u32> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Get directory information for a single file or directory within a parent directory.
    ///
    /// This method is only called when [VolumeParams::pass_query_directory_filename](crate::host::VolumeParams::pass_query_directory_filename)
    /// is set to true, and the file system was created with [FileSystemParams::use_dir_info_by_name](crate::host::FileSystemParams).
    /// set to true.
    fn get_dir_info_by_name(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        out_dir_info: &mut DirInfo,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Get information about the volume.
    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Set the volume label.
    fn set_volume_label(&self, volume_label: &U16CStr, volume_info: &mut VolumeInfo) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Get information about named streams.
    fn get_stream_info(&self, context: &Self::FileContext, buffer: &mut [u8]) -> Result<u32> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Get reparse point information by its name.
    ///
    /// In the WinFSP C API, this method is usually called manually by the interface method
    /// `ResolveReparsePoints`. winfsp-rs automatically handles resolution of reparse points
    /// if this method is implemented properly.
    fn get_reparse_point_by_name(
        &self,
        file_name: &U16CStr,
        is_directory: bool,
        buffer: &mut [u8],
    ) -> Result<u64> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Get reparse point information.
    fn get_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &mut [u8],
    ) -> Result<u64> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Set reparse point information.
    fn set_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &[u8],
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Delete reparse point information.
    fn delete_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &[u8],
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Get extended attribute information.
    fn get_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
    ) -> Result<u32> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Set extended attribute information.
    fn set_extended_attributes(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        file_info: &mut FileInfo,
    ) -> Result<()> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Process a control code from the [`DeviceIoControl`](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol) API.
    fn control(
        &self,
        context: &Self::FileContext,
        control_code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<u32> {
        Err(STATUS_INVALID_DEVICE_REQUEST.into())
    }

    /// Inform the file system that its dispatcher has been stopped.
    ///
    /// If the dispatcher was stopped via the driver being unloaded, or
    /// otherwise some non-normal situation, `normally` will be false.
    ///
    /// Do not attempt to call [`FspFileSystemStopServiceIfNecessary`](winfsp_sys::FspFileSystemStopServiceIfNecessary),
    /// it will be called after this function ends. All cleanup done within this function
    /// should be user-mode only.
    fn dispatcher_stopped(&self, normally: bool) {}

    /// Get the context response of the current FSP interface operation.
    ///
    /// ## Safety
    /// This function may be used only when servicing one of the `FileSystemContext` operations.
    /// The current operation context is stored in thread local storage.
    ///
    /// ## Warning
    /// If implementing a filesystem, the default implementation should be sufficient for most if not
    /// all cases. Be careful if providing your own implementation.
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
    /// This function may be used only when servicing one of the `FileSystemContext` operations.
    /// The current operation context is stored in thread local storage.
    ///
    /// ## Warning
    /// If implementing a filesystem, the default implementation should be sufficient for most if not
    /// all cases. Be careful if providing your own implementation.
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

#[cfg_attr(feature = "docsrs", doc(cfg(feature = "async-io")))]
#[cfg(feature = "async-io")]

/// The trait that implements asynchronous file system operations for a WinFSP file system.
///
/// If an implementor of this trait panics in any of the methods,
/// the caller will receive `STATUS_NONCONTINUABLE_EXCEPTION` (0xC0000025).
///
/// Any non-implemented optional methods will return `STATUS_INVALID_DEVICE_REQUEST` (0xC0000010).
///
/// The default implementations simply call [`read`](FileSystemContext::read), [`write`](FileSystemContext::write),
/// and [`read_directory`](FileSystemContext::read_directory) on the base
/// `FileSystemContext` trait.
///
/// The filesystem host must be created with [`FileSystemHost::new_async`](crate::host::FileSystemHost::new_async)
/// or [`FileSystemHost::new_with_options_async`](crate::host::FileSystemHost::new_with_options_async), otherwise
/// the synchronous implementations will be used.
///
/// `AsyncFileSystemContext` is executor agnostic. Futures produced by [`read_async`](AsyncFileSystemContext::read_async),
/// [`write_async`](AsyncFileSystemContext::read_async), and
/// [`read_directory_async`](AsyncFileSystemContext::read_directory_async) will be passed to [`AsyncFileSystemContext::spawn_task`],
/// which is responsible for dispatching the task to the executor of the implementor's choice. It is recommended, but not required,
/// that the task executes on a separate thread, executing on the same thread may cause deadlocks.
#[allow(unused_variables)]
pub trait AsyncFileSystemContext: FileSystemContext + 'static + Sync
where
    <Self as FileSystemContext>::FileContext: Sync,
{
    /// Read from a file asynchronously. Return the number of bytes read.
    ///
    /// The default implementation for this simply calls the base `FileSystemContext::read`
    /// implementation.
    fn read_async(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> impl std::future::Future<Output = Result<u32>> + Send {
        async move { Self::read(self, context, buffer, offset) }
    }

    /// Write to a file asynchronously. Return the number of bytes written.
    ///
    /// The default implementation for this simply calls the base `FileSystemContext::write`
    /// implementation.
    fn write_async(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> impl std::future::Future<Output = Result<u32>> + Send {
        async move {
            Self::write(
                self,
                context,
                buffer,
                offset,
                write_to_eof,
                constrained_io,
                file_info,
            )
        }
    }

    /// Read directory entries from a directory handle asynchronously.
    fn read_directory_async(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> impl std::future::Future<Output = Result<u32>> + Send {
        async move { Self::read_directory(self, context, pattern, marker, buffer) }
    }

    /// Spawn a task onto the local executor.
    ///
    /// The implementations of `read_async`, `write_async`, and `read_directory_async` must
    /// be compatible with the executor the future is spawned on.
    fn spawn_task(&self, future: impl std::future::Future<Output = ()> + Send + 'static);
}
