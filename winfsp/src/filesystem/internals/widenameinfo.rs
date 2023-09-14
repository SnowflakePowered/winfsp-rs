use crate::{Result, U16CStr};
use std::ffi::OsStr;
use std::iter;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::STATUS_INSUFFICIENT_RESOURCES;

pub trait WideNameInfoInternal<const BUFFER_SIZE: usize = 255>:
    crate::filesystem::sealed::Sealed
{
    #[doc(hidden)]
    /// Return a reference to the name buffer.
    fn name_buffer(&mut self) -> &mut [u16; BUFFER_SIZE];

    #[doc(hidden)]
    /// Set the size of the entry.
    fn set_size(&mut self, buffer_size: u16);

    #[doc(hidden)]
    fn add_to_buffer_internal(entry: Option<&Self>, buffer: &mut [u8], cursor: &mut u32) -> bool;
}

/// A information entry that contains a wide name buffer.
pub trait WideNameInfo<const BUFFER_SIZE: usize = 255>:
    crate::filesystem::sealed::Sealed + WideNameInfoInternal<BUFFER_SIZE>
{
    /// Finalize the buffer, indicating that no more entries are to be written.
    ///
    /// If successful, returns true, otherwise false indicates that no more entries
    /// can be accepted into the buffer.
    fn finalize_buffer(buffer: &mut [u8], cursor: &mut u32) -> bool {
        Self::add_to_buffer_internal(None, buffer, cursor)
    }

    /// Append the information entry into the provided buffer.
    ///
    /// If successful, returns true. If the buffer is too small to store any more entries,
    /// returns false. The provided cursor should be reused into the next call
    /// to `append_to_buffer`.
    fn append_to_buffer(&self, buffer: &mut [u8], cursor: &mut u32) -> bool {
        Self::add_to_buffer_internal(Some(self), buffer, cursor)
    }

    /// Reset the contents of the entry.
    fn reset(&mut self);

    /// Write the name of the entry as raw u16 bytes.
    ///
    /// If the input buffer is not null terminated, and the buffer
    /// was not reset prior to setting the name, the previous contents
    /// of the buffer will remain, however it is not memory unsafe to
    /// do so.
    ///
    /// If the input buffer is too large, this function will return
    /// `STATUS_INSUFFICIENT_RESOURCES`.
    fn set_name_raw<'a, P: Into<&'a [u16]>>(&mut self, file_name: P) -> Result<()> {
        let file_name = file_name.into();
        if file_name.len() > BUFFER_SIZE {
            return Err(STATUS_INSUFFICIENT_RESOURCES.into());
        }
        self.name_buffer()[0..std::cmp::min(file_name.len(), BUFFER_SIZE)]
            .copy_from_slice(&file_name[0..std::cmp::min(file_name.len(), BUFFER_SIZE)]);
        self.set_size(std::mem::size_of_val(file_name) as u16);
        Ok(())
    }

    /// Write the name of the entry into the name buffer.
    fn set_name<P: AsRef<OsStr>>(&mut self, file_name: P) -> Result<()> {
        let file_name = file_name.as_ref();
        let file_name = file_name
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<_>>();
        self.set_name_raw(file_name.as_slice())
    }

    /// Write the name of the entry into the name buffer with an input wide CStr.
    fn set_name_cstr<P: AsRef<U16CStr>>(&mut self, file_name: P) -> Result<()> {
        let file_name = file_name.as_ref();
        self.set_name_raw(file_name.as_slice_with_nul())
    }
}
