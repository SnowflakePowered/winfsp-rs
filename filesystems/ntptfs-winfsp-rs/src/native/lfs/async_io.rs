//! Cancellation-safe wrappers around overlapped NT I/O.
//!
//! ## Why is this file shaped like this?
//!
//! `NtReadFile` / `NtWriteFile` / `NtQueryDirectoryFile` are overlapped I/O
//! primitives. When they return `STATUS_PENDING`, the kernel keeps the
//! `IO_STATUS_BLOCK` pointer AND the user-buffer pointer until the I/O
//! actually completes. If the surrounding `Future` is dropped before that —
//! e.g. inside `tokio::select!`, `tokio::time::timeout`, or executor shutdown —
//! the kernel will eventually write into freed/reused memory. That is a UAF.
//!
//! The fix here is to make every in-flight I/O own its `IO_STATUS_BLOCK` and
//! data buffer on the heap (`Box<UnsafeCell<IO_STATUS_BLOCK>>` / `Box<[u8]>`),
//! never borrowing the caller's buffer for the kernel call. On a normal
//! completion the public wrapper memcpys our owned buffer back to the
//! caller's slice. On `Drop` while still pending we hand the heap state off
//! to a process-threadpool wait that fires when the kernel finally signals
//! the event, at which point the wait callback drops the iosb + buffer boxes
//! and closes the event. `Drop` itself returns immediately, so it never
//! blocks the executor.
//!
//! These `lfs_*_async` functions are crate-internal — there are no external
//! callers, so the API is free to memcpy in/out behind the public
//! `&mut [u8]` / `&[u8]` facade.

use crate::native::lfs;
use parking_lot::Mutex;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::future::Future;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::ptr::addr_of;
use std::task::{Context, Poll, Waker};
use widestring::U16CStr;
use windows::Wdk::Storage::FileSystem::{
    FILE_INFORMATION_CLASS, NtCancelIoFileEx, NtQueryDirectoryFile, NtReadFile, NtWriteFile,
};
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, NTSTATUS, STATUS_ABANDONED, STATUS_PENDING, STATUS_SUCCESS,
    UNICODE_STRING, WAIT_ABANDONED, WAIT_ABANDONED_0, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::Threading::{
    CloseThreadpoolWait, CreateThreadpoolWait, INFINITE, PTP_CALLBACK_INSTANCE, PTP_WAIT,
    SetThreadpoolWait, WaitForSingleObject, WaitForThreadpoolWaitCallbacks,
};
use windows::Win32::System::WindowsProgramming::RtlInitUnicodeString;
use windows::core::PCWSTR;
use winfsp::FspError;
use winfsp::util::{AtomicHandle, NtHandleDrop};

/// Heap-owned state for a single overlapped I/O.
///
/// `iosb` and `buffer` are addressed directly by the kernel for the duration
/// of the I/O; their stable heap addresses outlive both the surrounding
/// `Future` and any cancellation, which is the whole point of this module.
struct InflightIo {
    event: HANDLE,
    file: HANDLE,
    iosb: Box<UnsafeCell<IO_STATUS_BLOCK>>,
    buffer: Box<[u8]>,
}

// SAFETY: All fields are either owned heap allocations or thread-agnostic
// Windows handle values. We hand an `InflightIo` from the dropping future to
// a threadpool callback exactly once (via `detach_pending`); after that
// hand-off nothing else aliases it.
unsafe impl Send for InflightIo {}

/// Drop case for an in-flight overlapped I/O.
///
/// Cancels the pending operation, then registers a threadpool wait that will
/// free the `InflightIo` (closing the event and dropping the iosb + buffer
/// boxes) once the kernel signals the event. The dropping thread returns
/// immediately; no blocking.
unsafe fn detach_pending(state: InflightIo) {
    let raw = Box::into_raw(Box::new(state));

    // Best-effort cancel to shorten the time we hold the heap allocations
    // alive. If the I/O has already completed this fails harmlessly; the
    // threadpool wait below still finishes the right thing.
    unsafe {
        let mut cancel_iosb: IO_STATUS_BLOCK = std::mem::zeroed();
        let _ = NtCancelIoFileEx(
            (*raw).file,
            Some((*raw).iosb.get() as *const _),
            &mut cancel_iosb,
        );
    }

    let wait = match unsafe {
        CreateThreadpoolWait(Some(inflight_complete), Some(raw.cast::<c_void>()), None)
    } {
        Ok(w) => w,
        Err(_) => {
            // Couldn't register a threadpool wait (extremely rare). Fall
            // back to blocking this thread until the kernel finishes, so
            // we still avoid the UAF.
            unsafe {
                let _ = WaitForSingleObject((*raw).event, INFINITE);
                let boxed = Box::from_raw(raw);
                let _ = CloseHandle(boxed.event);
            }
            return;
        }
    };

    // Hand the state off to the threadpool. After this point the threadpool
    // owns `raw`; `inflight_complete` will free it.
    unsafe { SetThreadpoolWait(wait, Some((*raw).event), None) };
}

/// Threadpool callback that runs once the kernel has signaled completion of
/// a detached (cancelled) I/O. At this point the kernel has released its
/// pointers into `state.iosb` and `state.buffer`, so we can safely drop them.
unsafe extern "system" fn inflight_complete(
    _instance: PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    wait: PTP_WAIT,
    _wait_result: u32,
) {
    // SAFETY: `context` is the `Box<InflightIo>` raw pointer leaked into the
    // threadpool by `detach_pending`. The threadpool fires this callback
    // exactly once for a one-shot wait, so taking ownership here is sound.
    let state: Box<InflightIo> = unsafe { Box::from_raw(context.cast()) };
    unsafe {
        let _ = CloseHandle(state.event);
        // Closing the wait from inside its own callback is documented as
        // safe for one-shot waits.
        CloseThreadpoolWait(wait);
    }
    // `state` drops here, freeing iosb and buffer boxes.
}

/// Shared waker slot for the polling threadpool wait.
///
/// The future writes its current `Waker` here on each poll that returns
/// `Pending`; the threadpool callback consumes it when the kernel signals
/// completion. Synchronisation is via `Mutex` because poll runs on an
/// executor thread while the callback runs on a process-threadpool thread.
struct WaiterState {
    waker: Mutex<Option<Waker>>,
}

/// Owns a threadpool wait registered on the I/O event. When the event
/// becomes signalled the threadpool calls [`wake_waiter`], which wakes the
/// future. `Drop` synchronously drains any in-flight callback and closes the
/// wait object, so by the time `Drop` returns the boxed [`WaiterState`] can
/// be safely freed.
struct Waiter {
    wait: PTP_WAIT,
    state: Box<WaiterState>,
}

// SAFETY: `PTP_WAIT` and `Box<WaiterState>` are both Send. The threadpool
// only accesses `state` through the raw pointer we hand it; the future
// updates `state.waker` under its `Mutex`.
unsafe impl Send for Waiter {}

impl Waiter {
    /// Register a threadpool wait on `event` that will call `waker.wake()`
    /// once the event becomes signalled. Returns `None` if `CreateThreadpoolWait`
    /// fails — in that case the caller should fall back to busy-polling so
    /// the I/O eventually completes.
    fn register(event: HANDLE, waker: Waker) -> Option<Self> {
        let state = Box::new(WaiterState {
            waker: Mutex::new(Some(waker)),
        });
        // Stable address of the WaiterState — the box is owned by `Waiter`,
        // so as long as `Waiter` outlives the wait callbacks the pointer is
        // valid.
        let ctx_ptr = (&*state) as *const WaiterState as *mut c_void;
        let wait = match unsafe { CreateThreadpoolWait(Some(wake_waiter), Some(ctx_ptr), None) } {
            Ok(w) => w,
            Err(_) => return None,
        };
        unsafe { SetThreadpoolWait(wait, Some(event), None) };
        Some(Self { wait, state })
    }

    /// Replace the stored waker with `waker`. Called on every re-poll so the
    /// callback wakes the *current* task even if the executor handed us a
    /// fresh `Waker` since the last poll.
    fn refresh(&self, waker: &Waker) {
        *self.state.waker.lock() = Some(waker.clone());
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        // Synchronise with the threadpool: cancel pending callbacks and
        // block until any in-flight callback finishes. After this returns
        // no thread is reading `self.state`, so the box drops safely.
        unsafe {
            WaitForThreadpoolWaitCallbacks(self.wait, true);
            CloseThreadpoolWait(self.wait);
        }
    }
}

unsafe extern "system" fn wake_waiter(
    _instance: PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    _wait: PTP_WAIT,
    _wait_result: u32,
) {
    // SAFETY: `context` points into the `Box<WaiterState>` owned by a live
    // `Waiter`. `Waiter::Drop` calls `WaitForThreadpoolWaitCallbacks` before
    // freeing the box, so this reference cannot outlive the box.
    let state = unsafe { &*(context as *const WaiterState) };
    if let Some(w) = state.waker.lock().take() {
        w.wake();
    }
}

/// Non-blocking observation of the event + iosb status. Returns `Some(status)`
/// if the kernel has signaled completion, `None` if the I/O is still pending.
fn observe_completion(event: HANDLE, iosb: *mut IO_STATUS_BLOCK) -> Option<NTSTATUS> {
    let wait_result = unsafe { WaitForSingleObject(event, 0) };
    if wait_result == WAIT_OBJECT_0 {
        let code = unsafe { addr_of!((*iosb).Anonymous.Status).read() };
        Some(code)
    } else if wait_result == WAIT_FAILED
        || wait_result == WAIT_ABANDONED
        || wait_result == WAIT_ABANDONED_0
    {
        Some(STATUS_ABANDONED)
    } else {
        None
    }
}

/// Ensure a threadpool wait is armed on `event` and that its stored waker is
/// the current task's. Called from every `poll` that is about to return
/// `Pending`.
///
/// On `CreateThreadpoolWait` failure (extremely rare) the slot stays `None`
/// and we fall back to busy-waking the current task; the I/O will still
/// complete, just less efficiently.
fn arm_waiter(slot: &mut Option<Waiter>, event: HANDLE, cx: &Context<'_>) {
    match slot {
        Some(w) => w.refresh(cx.waker()),
        None => match Waiter::register(event, cx.waker().clone()) {
            Some(w) => *slot = Some(w),
            None => cx.waker().wake_by_ref(),
        },
    }
}

/// Common `Drop` body: if the I/O is still pending in the kernel, detach to
/// the threadpool; otherwise just close the event and let the heap allocations
/// drop normally.
fn drop_inflight(inflight: Option<InflightIo>, result: Option<NTSTATUS>) {
    let Some(state) = inflight else { return };
    if matches!(result, Some(s) if s == STATUS_PENDING) {
        unsafe { detach_pending(state) };
    } else {
        unsafe {
            let _ = CloseHandle(state.event);
        }
    }
}

// --------------------------------- READ ---------------------------------

struct LfsReadFuture {
    inflight: Option<InflightIo>,
    result: Option<NTSTATUS>,
    offset: i64,
    waiter: Option<Waiter>,
}

// SAFETY: All fields are Send (see `InflightIo` and `Waiter` Send impls).
unsafe impl Send for LfsReadFuture {}

impl LfsReadFuture {
    fn new(file: HANDLE, buf_len: usize, offset: i64) -> winfsp::Result<Self> {
        let event = lfs::new_event()?;
        let buffer = vec![0u8; buf_len].into_boxed_slice();
        Ok(Self {
            inflight: Some(InflightIo {
                event,
                file,
                iosb: Box::new(UnsafeCell::new(IO_STATUS_BLOCK::default())),
                buffer,
            }),
            result: None,
            offset,
            waiter: None,
        })
    }
}

impl Drop for LfsReadFuture {
    fn drop(&mut self) {
        // Drop the polling waiter first — its Drop synchronously joins any
        // in-flight callback, so the boxed WaiterState can be freed before
        // we touch the inflight state.
        self.waiter = None;
        drop_inflight(self.inflight.take(), self.result);
    }
}

impl Future for LfsReadFuture {
    type Output = winfsp::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();

        loop {
            // First poll: kick off the NT call.
            if this.result.is_none() {
                let offset = this.offset;
                let inflight = this.inflight.as_mut().expect("inflight taken");
                let initial = unsafe {
                    NtReadFile(
                        inflight.file,
                        Some(inflight.event),
                        None,
                        None,
                        inflight.iosb.get(),
                        inflight.buffer.as_mut_ptr().cast(),
                        inflight.buffer.len() as u32,
                        Some(&offset),
                        None,
                    )
                };
                this.result = Some(initial);
                continue;
            }

            let result = this.result.unwrap();
            if result != STATUS_PENDING {
                let inflight = this.inflight.as_ref().expect("inflight taken");
                return if result != STATUS_SUCCESS {
                    Poll::Ready(Err(FspError::from(result)))
                } else {
                    let info = unsafe { (*inflight.iosb.get()).Information };
                    Poll::Ready(Ok(info))
                };
            }

            // Pending. Re-check the event one last time before sleeping so we
            // don't miss a signal that arrived between two polls.
            let observed = {
                let inflight = this.inflight.as_ref().expect("inflight taken");
                observe_completion(inflight.event, inflight.iosb.get())
            };
            if let Some(code) = observed {
                this.result = Some(code);
                continue;
            }

            // Arm the threadpool wait (or refresh its stored waker).
            arm_waiter(&mut this.waiter, this.inflight.as_ref().unwrap().event, cx);
            return Poll::Pending;
        }
    }
}

pub async fn lfs_read_file_async(
    handle: &AtomicHandle<NtHandleDrop>,
    dst: &mut [u8],
    offset: u64,
    bytes_transferred: &mut u32,
) -> winfsp::Result<()> {
    let mut future = LfsReadFuture::new(HANDLE(handle.handle()), dst.len(), offset as i64)?;
    let n = (&mut future).await?;
    // Copy out of the owned buffer directly into `dst` before `future` drops.
    let inflight = future.inflight.as_ref().expect("inflight taken");
    dst[..n].copy_from_slice(&inflight.buffer[..n]);
    *bytes_transferred = n as u32;
    Ok(())
}

// --------------------------------- WRITE --------------------------------

struct LfsWriteFuture {
    inflight: Option<InflightIo>,
    result: Option<NTSTATUS>,
    offset: i64,
    waiter: Option<Waiter>,
}

unsafe impl Send for LfsWriteFuture {}

impl LfsWriteFuture {
    fn new(file: HANDLE, owned: Box<[u8]>, offset: i64) -> winfsp::Result<Self> {
        let event = lfs::new_event()?;
        Ok(Self {
            inflight: Some(InflightIo {
                event,
                file,
                iosb: Box::new(UnsafeCell::new(IO_STATUS_BLOCK::default())),
                buffer: owned,
            }),
            result: None,
            offset,
            waiter: None,
        })
    }
}

impl Drop for LfsWriteFuture {
    fn drop(&mut self) {
        self.waiter = None;
        drop_inflight(self.inflight.take(), self.result);
    }
}

impl Future for LfsWriteFuture {
    type Output = winfsp::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();

        loop {
            if this.result.is_none() {
                let offset = this.offset;
                let inflight = this.inflight.as_mut().expect("inflight taken");
                let initial = unsafe {
                    NtWriteFile(
                        inflight.file,
                        Some(inflight.event),
                        None,
                        None,
                        inflight.iosb.get(),
                        inflight.buffer.as_ptr().cast(),
                        inflight.buffer.len() as u32,
                        Some(&offset),
                        None,
                    )
                };
                this.result = Some(initial);
                continue;
            }

            let result = this.result.unwrap();
            if result != STATUS_PENDING {
                let inflight = this.inflight.as_ref().expect("inflight taken");
                return if result != STATUS_SUCCESS {
                    Poll::Ready(Err(FspError::from(result)))
                } else {
                    let info = unsafe { (*inflight.iosb.get()).Information };
                    Poll::Ready(Ok(info))
                };
            }

            let observed = {
                let inflight = this.inflight.as_ref().expect("inflight taken");
                observe_completion(inflight.event, inflight.iosb.get())
            };
            if let Some(code) = observed {
                this.result = Some(code);
                continue;
            }

            arm_waiter(&mut this.waiter, this.inflight.as_ref().unwrap().event, cx);
            return Poll::Pending;
        }
    }
}

pub async fn lfs_write_file_async(
    handle: &AtomicHandle<NtHandleDrop>,
    src: &[u8],
    offset: u64,
    bytes_transferred: &mut u32,
) -> winfsp::Result<()> {
    // Copy the source bytes into an owned buffer. After this point the caller
    // can do whatever they want with `src` — the kernel reads from `owned`.
    let owned: Box<[u8]> = src.to_vec().into_boxed_slice();
    let mut future = LfsWriteFuture::new(HANDLE(handle.handle()), owned, offset as i64)?;
    let n = (&mut future).await?;
    *bytes_transferred = n as u32;
    Ok(())
}

// ----------------------------- QUERY DIRECTORY --------------------------

struct LfsQueryDirectoryFileFuture<'a> {
    inflight: Option<InflightIo>,
    result: Option<NTSTATUS>,
    file_name: Option<&'a U16CStr>,
    return_single_entry: bool,
    restart_scan: bool,
    class: FILE_INFORMATION_CLASS,
    waiter: Option<Waiter>,
}

// SAFETY: HANDLEs in `inflight` are thread-agnostic; the borrowed `&U16CStr`
// is Send because `[u16]` is Sync.
unsafe impl<'a> Send for LfsQueryDirectoryFileFuture<'a> {}

impl<'a> LfsQueryDirectoryFileFuture<'a> {
    fn new(
        file: HANDLE,
        buf_len: usize,
        file_name: Option<&'a U16CStr>,
        return_single_entry: bool,
        restart_scan: bool,
        class: FILE_INFORMATION_CLASS,
    ) -> winfsp::Result<Self> {
        let event = lfs::new_event()?;
        let buffer = vec![0u8; buf_len].into_boxed_slice();
        Ok(Self {
            inflight: Some(InflightIo {
                event,
                file,
                iosb: Box::new(UnsafeCell::new(IO_STATUS_BLOCK::default())),
                buffer,
            }),
            result: None,
            file_name,
            return_single_entry,
            restart_scan,
            class,
            waiter: None,
        })
    }
}

impl<'a> Drop for LfsQueryDirectoryFileFuture<'a> {
    fn drop(&mut self) {
        self.waiter = None;
        drop_inflight(self.inflight.take(), self.result);
    }
}

impl<'a> Future for LfsQueryDirectoryFileFuture<'a> {
    type Output = winfsp::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();

        loop {
            if this.result.is_none() {
                // Build the UNICODE_STRING locally. The kernel captures the
                // input strings during the syscall (before returning STATUS_*),
                // so this does not need to outlive the call.
                let unicode_filename = this.file_name.map(|f| unsafe {
                    let mut u: MaybeUninit<UNICODE_STRING> = MaybeUninit::zeroed();
                    RtlInitUnicodeString(u.as_mut_ptr(), PCWSTR(f.as_ptr()));
                    u.assume_init()
                });
                let class = this.class;
                let return_single_entry = this.return_single_entry;
                let restart_scan = this.restart_scan;
                let inflight = this.inflight.as_mut().expect("inflight taken");
                let initial = unsafe {
                    NtQueryDirectoryFile(
                        inflight.file,
                        Some(inflight.event),
                        None,
                        None,
                        inflight.iosb.get(),
                        inflight.buffer.as_mut_ptr().cast(),
                        inflight.buffer.len() as u32,
                        class,
                        return_single_entry,
                        unicode_filename
                            .as_ref()
                            .map(|p| p as *const UNICODE_STRING as *const _),
                        restart_scan,
                    )
                };
                this.result = Some(initial);
                continue;
            }

            let result = this.result.unwrap();
            if result != STATUS_PENDING {
                let inflight = this.inflight.as_ref().expect("inflight taken");
                return if result != STATUS_SUCCESS {
                    Poll::Ready(Err(FspError::from(result)))
                } else {
                    let info = unsafe { (*inflight.iosb.get()).Information };
                    Poll::Ready(Ok(info))
                };
            }

            let observed = {
                let inflight = this.inflight.as_ref().expect("inflight taken");
                observe_completion(inflight.event, inflight.iosb.get())
            };
            if let Some(code) = observed {
                this.result = Some(code);
                continue;
            }

            arm_waiter(&mut this.waiter, this.inflight.as_ref().unwrap().event, cx);
            return Poll::Pending;
        }
    }
}

pub async fn lfs_query_directory_file_async(
    handle: &AtomicHandle<NtHandleDrop>,
    dst: &mut [u8],
    class: FILE_INFORMATION_CLASS,
    return_single_entry: bool,
    file_name: Option<&U16CStr>,
    restart_scan: bool,
) -> winfsp::Result<usize> {
    let mut future = LfsQueryDirectoryFileFuture::new(
        HANDLE(handle.handle()),
        dst.len(),
        file_name,
        return_single_entry,
        restart_scan,
        class,
    )?;
    let n = (&mut future).await?;
    let inflight = future.inflight.as_ref().expect("inflight taken");
    dst[..n].copy_from_slice(&inflight.buffer[..n]);
    Ok(n)
}
