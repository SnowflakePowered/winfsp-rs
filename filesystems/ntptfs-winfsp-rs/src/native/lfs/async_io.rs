use crate::native::lfs;
use std::cell::UnsafeCell;
use std::future::Future;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::ptr::addr_of;
use std::task::{Context, Poll};
use widestring::U16CStr;
use windows::Wdk::Storage::FileSystem::{
    FILE_INFORMATION_CLASS, NtQueryDirectoryFile, NtReadFile, NtWriteFile,
};
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, NTSTATUS, STATUS_ABANDONED, STATUS_PENDING, STATUS_SUCCESS,
    UNICODE_STRING, WAIT_ABANDONED, WAIT_ABANDONED_0, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::System::WindowsProgramming::RtlInitUnicodeString;
use windows::core::PCWSTR;
use winfsp::FspError;
use winfsp::util::{AtomicHandle, NtHandleDrop};

struct LfsReadFuture<'a> {
    event: AssertThreadSafe<HANDLE>,
    file: AssertThreadSafe<HANDLE>,
    iosb: UnsafeCell<AssertThreadSafe<IO_STATUS_BLOCK>>,
    result: Option<NTSTATUS>,
    buffer: &'a mut [u8],
    offset: i64,
}

#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct AssertThreadSafe<T>(pub T);

unsafe impl<T> Send for AssertThreadSafe<T> {}

impl<'a> LfsReadFuture<'a> {
    fn new(
        file: AssertThreadSafe<HANDLE>,
        buffer: &'a mut [u8],
        offset: i64,
    ) -> winfsp::Result<Self> {
        let event = AssertThreadSafe(lfs::new_event()?);
        Ok(Self {
            event,
            file,
            iosb: UnsafeCell::new(AssertThreadSafe(IO_STATUS_BLOCK::default())),
            result: None,
            buffer,
            offset,
        })
    }
}

impl<'a> Drop for LfsReadFuture<'a> {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.event.0);
        }
    }
}

impl<'a> Future for LfsReadFuture<'a> {
    type Output = Result<IO_STATUS_BLOCK, FspError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(result) = self.result else {
            let initial_result = unsafe {
                NtReadFile(
                    self.file.0,
                    Some(self.event.0),
                    None,
                    None,
                    self.iosb.get() as *mut _,
                    self.buffer.as_mut_ptr() as *mut _,
                    self.buffer.len() as u32,
                    Some(&self.offset),
                    None,
                )
            };
            self.result = Some(initial_result);
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };

        if result != STATUS_PENDING {
            return if result != STATUS_SUCCESS {
                Poll::Ready(Err(FspError::from(result)))
            } else {
                Poll::Ready(Ok(unsafe { self.iosb.get().read().0 }))
            };
        }

        let wait_result = unsafe { WaitForSingleObject(self.event.0, 0) };

        if wait_result == WAIT_OBJECT_0 {
            let code = unsafe { addr_of!((*self.iosb.get()).0.Anonymous.Status).read() };
            self.result = Some(code);
        } else if wait_result == WAIT_FAILED
            || wait_result == WAIT_ABANDONED
            || wait_result == WAIT_ABANDONED_0
        {
            self.result = Some(STATUS_ABANDONED);
        }

        // if timed out, io isn't ready
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

pub async fn lfs_read_file_async(
    handle: &AtomicHandle<NtHandleDrop>,
    buffer: &mut [u8],
    offset: u64,
    bytes_transferred: &mut u32,
) -> winfsp::Result<()> {
    let handle = AssertThreadSafe(HANDLE(handle.handle()));
    let transferred = async move {
        let lfs = LfsReadFuture::new(handle, buffer, offset as i64)?;
        lfs.await.map(|iosb| iosb.Information)
    }
    .await?;

    *bytes_transferred = transferred as u32;

    Ok(())
}

struct LfsWriteFuture<'a> {
    event: AssertThreadSafe<HANDLE>,
    file: AssertThreadSafe<HANDLE>,
    iosb: UnsafeCell<AssertThreadSafe<IO_STATUS_BLOCK>>,
    result: Option<NTSTATUS>,
    buffer: &'a [u8],
    offset: i64,
}

impl<'a> LfsWriteFuture<'a> {
    fn new(file: HANDLE, buffer: &'a [u8], offset: i64) -> winfsp::Result<Self> {
        let event = AssertThreadSafe(lfs::new_event()?);

        Ok(Self {
            event,
            file: AssertThreadSafe(file),
            iosb: UnsafeCell::new(AssertThreadSafe(IO_STATUS_BLOCK::default())),
            result: None,
            buffer,
            offset,
        })
    }
}

impl<'a> Drop for LfsWriteFuture<'a> {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.event.0);
        }
    }
}

impl<'a> Future for LfsWriteFuture<'a> {
    type Output = Result<IO_STATUS_BLOCK, FspError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(result) = self.result else {
            let initial_result = unsafe {
                NtWriteFile(
                    self.file.0,
                    Some(self.event.0),
                    None,
                    None,
                    self.iosb.get() as *mut _,
                    self.buffer.as_ptr() as *const _,
                    self.buffer.len() as u32,
                    Some(&self.offset),
                    None,
                )
            };
            self.result = Some(initial_result);
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };

        if result != STATUS_PENDING {
            return if result != STATUS_SUCCESS {
                Poll::Ready(Err(FspError::from(result)))
            } else {
                Poll::Ready(Ok(unsafe { self.iosb.get().read().0 }))
            };
        }

        let wait_result = unsafe { WaitForSingleObject(self.event.0, 0) };

        if wait_result == WAIT_OBJECT_0 {
            let code = unsafe { addr_of!((*self.iosb.get()).0.Anonymous.Status).read() };
            self.result = Some(code);
        } else if wait_result == WAIT_FAILED
            || wait_result == WAIT_ABANDONED
            || wait_result == WAIT_ABANDONED_0
        {
            self.result = Some(STATUS_ABANDONED);
        }

        // if timed out, io isn't ready
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

pub async fn lfs_write_file_async(
    handle: &AtomicHandle<NtHandleDrop>,
    buffer: &[u8],
    offset: u64,
    bytes_transferred: &mut u32,
) -> winfsp::Result<()> {
    let transferred = async move {
        let lfs = LfsWriteFuture::new(HANDLE(handle.handle()), buffer, offset as i64)?;
        lfs.await.map(|iosb| iosb.Information)
    }
    .await?;

    *bytes_transferred = transferred as u32;

    Ok(())
}

struct LfsQueryDirectoryFileFuture<'a> {
    file: AssertThreadSafe<HANDLE>,
    event: AssertThreadSafe<HANDLE>,
    file_name: Option<&'a U16CStr>,
    iosb: UnsafeCell<AssertThreadSafe<IO_STATUS_BLOCK>>,
    result: Option<NTSTATUS>,
    buffer: &'a mut [u8],
    return_single_entry: bool,
    restart_scan: bool,
    class: FILE_INFORMATION_CLASS,
}

impl<'a> LfsQueryDirectoryFileFuture<'a> {
    fn new(
        file: HANDLE,
        file_name: Option<&'a U16CStr>,
        buffer: &'a mut [u8],
        return_single_entry: bool,
        restart_scan: bool,
        class: FILE_INFORMATION_CLASS,
    ) -> winfsp::Result<Self> {
        let event = lfs::new_event()?;

        Ok(Self {
            file: AssertThreadSafe(file),
            event: AssertThreadSafe(event),
            file_name,
            iosb: UnsafeCell::new(AssertThreadSafe(IO_STATUS_BLOCK::default())),
            result: None,
            buffer,
            return_single_entry,
            restart_scan,
            class,
        })
    }
}

impl<'a> Drop for LfsQueryDirectoryFileFuture<'a> {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.event.0);
        }
    }
}

impl<'a> Future for LfsQueryDirectoryFileFuture<'a> {
    type Output = Result<IO_STATUS_BLOCK, FspError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(result) = self.result else {
            let unicode_filename = self.file_name.map(|f| unsafe {
                let mut unicode_filename: MaybeUninit<UNICODE_STRING> = MaybeUninit::zeroed();
                RtlInitUnicodeString(unicode_filename.as_mut_ptr(), PCWSTR(f.as_ptr()));
                unicode_filename.assume_init()
            });

            let initial_result = unsafe {
                NtQueryDirectoryFile(
                    self.file.0,
                    Some(self.event.0),
                    None,
                    None,
                    self.iosb.get() as *mut _,
                    self.buffer.as_mut_ptr() as *mut _,
                    self.buffer.len() as u32,
                    self.class,
                    self.return_single_entry,
                    unicode_filename
                        .as_ref()
                        .map(|p| p as *const UNICODE_STRING as *const _),
                    self.restart_scan,
                )
            };
            self.result = Some(initial_result);
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };

        if result != STATUS_PENDING {
            return if result != STATUS_SUCCESS {
                Poll::Ready(Err(FspError::from(result)))
            } else {
                Poll::Ready(Ok(unsafe { self.iosb.get().read().0 }))
            };
        }

        let wait_result = unsafe { WaitForSingleObject(self.event.0, 0) };

        if wait_result == WAIT_OBJECT_0 {
            let code = unsafe { addr_of!((*self.iosb.get()).0.Anonymous.Status).read() };
            self.result = Some(code);
        } else if wait_result == WAIT_FAILED
            || wait_result == WAIT_ABANDONED
            || wait_result == WAIT_ABANDONED_0
        {
            self.result = Some(STATUS_ABANDONED);
        }

        // if timed out, io isn't ready
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

pub async fn lfs_query_directory_file_async(
    handle: &AtomicHandle<NtHandleDrop>,
    buffer: &mut [u8],
    class: FILE_INFORMATION_CLASS,
    return_single_entry: bool,
    file_name: Option<&U16CStr>,
    restart_scan: bool,
) -> winfsp::Result<usize> {
    let query_ft = LfsQueryDirectoryFileFuture::new(
        HANDLE(handle.handle()),
        file_name,
        buffer,
        return_single_entry,
        restart_scan,
        class,
    )?;
    let iosb = query_ft.await?;

    Ok(iosb.Information)
}
