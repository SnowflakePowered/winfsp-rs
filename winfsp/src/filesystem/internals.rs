use std::ffi::OsStr;
use std::iter;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::STATUS_INSUFFICIENT_RESOURCES;
// todo: safe wrappers
pub use winfsp_sys::{
    FSP_FSCTL_FILE_INFO, FSP_FSCTL_OPEN_FILE_INFO,
    FSP_FSCTL_VOLUME_INFO, FSP_FSCTL_VOLUME_PARAMS,
};

use crate::{Result, WCStr};

/// A information entry that contains a wide name buffer.
pub trait WideNameInfo<const BUFFER_SIZE: usize>: super::sealed::Sealed {

    #[doc(hidden)]
    /// Return a reference to the name buffer.
    fn name_buffer(&mut self) -> &mut [u16; BUFFER_SIZE];

    #[doc(hidden)]
    /// Set the size of the entry.
    fn set_size(&mut self, buffer_size: u16);

    /// Reset the contents of the entry.
    fn reset(&mut self);

    /// Adds the entry to the provided buffer.
    fn add_to_buffer(entry: Option<&Self>, buffer: &mut [u8], cursor: &mut u32) -> bool;

    /// Write the name of the entry as raw u16 bytes..
    ///
    /// If the input buffer is not null terminated, potentially bad things could happen.
    ///
    /// # Safety
    /// The input buffer should either be null terminated or less than the size of the buffer.
    unsafe fn set_name_raw<'a, P: Into<&'a [u16]>>(&mut self, file_name: P) -> Result<()> {
        let file_name = file_name.into();
        if file_name.len() >= BUFFER_SIZE {
            return Err(STATUS_INSUFFICIENT_RESOURCES.into());
        }
        self.name_buffer()[0..std::cmp::min(file_name.len(), BUFFER_SIZE)]
            .copy_from_slice(&file_name[0..std::cmp::min(file_name.len(), BUFFER_SIZE)]);
        self.set_size((std::mem::size_of::<u16>() * file_name.len()) as u16);
        Ok(())
    }

    /// Write the name of the entry into the name buffer.
    fn set_name<P: AsRef<OsStr>>(&mut self, file_name: P) -> Result<()> {
        let file_name = file_name.as_ref();
        let file_name = file_name
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();
        unsafe { self.set_name_raw(file_name.as_slice()) }
    }

    /// Write the name of the entry into the name buffer with an input wide CStr.
    fn set_name_cstr<P: AsRef<WCStr>>(&mut self, file_name: P) -> Result<()> {
        let file_name = file_name.as_ref();
        unsafe { self.set_name_raw(file_name.as_slice_with_nul()) }
    }

}
