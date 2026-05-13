//! Async-only counterparts of `host::interface`.
//!
//! This module is only compiled with `feature = "async-io"`. It contains:
//!
//! * The `InFlightBarrier` wait-group + draining flag, used by
//!   `FileSystemHost::Drop` to ensure no spawned task outlives the
//!   FileSystemUserContext box.
//! * The `AsyncOpCtx` / `InjectOpCtx` machinery that lets user code call
//!   `with_operation_request` / `with_operation_response` from inside an
//!   `AsyncFileSystemContext` future, via a per-thread injection set on
//!   every `poll`.
//! * The three async `unsafe extern "C" fn` callbacks
//!   (`read_directory_async`, `read_async`, `write_async`) that the
//!   Interface vtable routes to.
//!
//! The synchronous Interface constructors live in `host::interface`; the
//! async constructors there import the three C callbacks from here.

use parking_lot::{Condvar, Mutex};
use std::cell::{Cell, UnsafeCell};
use std::future::Future;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::AtomicPtr;
use std::task::{Context, Poll};
use widestring::{U16CStr, U16CString};
use windows::Win32::Foundation::{
    STATUS_INSUFFICIENT_RESOURCES, STATUS_PENDING, STATUS_SUCCESS, STATUS_TRANSACTION_NOT_FOUND,
    STATUS_VOLUME_DISMOUNTED,
};
use winfsp_sys::{
    FSP_FILE_SYSTEM, FSP_FSCTL_FILE_INFO, FSP_FSCTL_TRANSACT_REQ, FSP_FSCTL_TRANSACT_RSP,
    NTSTATUS as FSP_STATUS, PVOID,
};

use crate::constants::FspTransactKind;
use crate::filesystem::{AsyncFileSystemContext, DirMarker, FileInfo, FileSystemContext};
use crate::host::interface::{FileSystemUserContext, assert_ctx, catch_panic};
use crate::util::VariableSizedBox;

// ============================================================================
// InFlightBarrier — wait-group with a draining flag.
//
// `FileSystemHost::Drop` calls `begin_drain_and_wait` to atomically (a)
// refuse subsequent `enter` calls and (b) park until every outstanding
// guard has been dropped. The draining flag closes the TOCTOU window in
// which a still-running WinFSP dispatcher could spawn one last task
// whose `&FileSystemUserContext` would otherwise be left dangling past
// `Box::from_raw` in Drop.
// ============================================================================

pub(crate) struct InFlightBarrier {
    state: Mutex<BarrierState>,
    quiesced: Condvar,
}

struct BarrierState {
    count: usize,
    draining: bool,
}

impl InFlightBarrier {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(BarrierState {
                count: 0,
                draining: false,
            }),
            quiesced: Condvar::new(),
        })
    }

    /// Bump the live-task count and hand back an RAII guard. Returns
    /// `None` if the host has begun draining — in that case the C
    /// callback should refuse the IRP rather than spawn a task whose
    /// `&FileSystemUserContext` will outlive the box.
    pub(crate) fn enter(self: &Arc<Self>) -> Option<InFlightGuard> {
        let mut s = self.state.lock();
        if s.draining {
            return None;
        }
        s.count += 1;
        Some(InFlightGuard(Arc::clone(self)))
    }

    /// Mark the barrier as draining and park until every outstanding
    /// `InFlightGuard` has been dropped. Called from
    /// `FileSystemHost::Drop` between dropping the notify timer and
    /// stopping the dispatcher.
    ///
    /// Setting `draining` and reading `count` happen under the same lock
    /// as `enter`'s read-check-increment, so no new task can slip past
    /// the drain.
    pub(crate) fn begin_drain_and_wait(&self) {
        let mut s = self.state.lock();
        s.draining = true;
        while s.count > 0 {
            self.quiesced.wait(&mut s);
        }
    }
}

/// RAII handle held inside each spawned async task. Dropping it (whether
/// by natural completion, executor cancellation, or panic unwind)
/// decrements the live-task count and wakes the host if it has reached
/// zero.
pub(crate) struct InFlightGuard(Arc<InFlightBarrier>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut s = self.0.state.lock();
        s.count -= 1;
        if s.count == 0 {
            self.0.quiesced.notify_all();
        }
    }
}

// ============================================================================
// Async operation-context injection.
//
// WinFSP stores the current operation's Request/Response pointers in TLS
// (`FspFileSystemGetOperationContext`). That TLS is only set on the
// dispatcher thread for the duration of the C callback — once we
// `spawn_task`, the future runs on the executor and the TLS is unset.
//
// To let user code call `with_operation_request` / `with_operation_response`
// from inside an `AsyncFileSystemContext` impl, we:
//   1. Snapshot the dispatcher's Request bytes into a heap-owned Box<[u8]>
//      *before* spawning, and build a framework-owned Response template.
//      WinFSP's own Request/Response buffers are reused across IRPs by the
//      dispatcher loop (`winfsp/src/dll/fs.c:284`), so retaining their
//      pointers across an `await` is unsound; an owned snapshot is.
//   2. Box up both as an `AsyncOpCtx` whose heap address is stable for the
//      lifetime of the spawned future.
//   3. Wrap the user's future with `InjectOpCtx`, which on every `poll`
//      installs a NonNull to that `AsyncOpCtx` in our own thread-local and
//      restores the previous value on poll exit (RAII).
//   4. Extend `with_operation_request` / `with_operation_response` to fall
//      back to that thread-local when WinFSP's TLS is unset.
//
// Because the TL is set on each poll (whichever thread the executor is
// polling on), the borrow stays "live" for any synchronous call the user
// makes inside their future body. The user can't hold the borrow across
// a `.await` — the FnOnce in `with_operation_*` consumes it.
// ============================================================================

pub(crate) struct AsyncFileOperationContext {
    /// Owned copy of the dispatcher's `FSP_FSCTL_TRANSACT_REQ`, sized to
    /// its on-wire `Size` field. The struct ends with
    /// `Buffer: __IncompleteArrayField<UINT8>`, a flexible array member,
    /// so the snapshot must keep the trailing bytes accessible — hence
    /// `VariableSizedBox` rather than a value copy.
    request: VariableSizedBox<FSP_FSCTL_TRANSACT_REQ>,
    /// Framework-owned response. Wrapped in `UnsafeCell` so the user can
    /// mutate it through `with_operation_response_async` while only holding
    /// `&AsyncFileOperationContext` (the TL hand-out path).
    ///
    /// Sized to [`FSP_FSCTL_TRANSACT_RSP_SIZEMAX`] — matching the
    /// dispatcher's own response buffer. `FSP_FSCTL_TRANSACT_RSP` ends in a
    /// `Buffer: __IncompleteArrayField<UINT8>` flex member, so user code
    /// servicing ops that write trailing payload (reparse info, security
    /// descriptors, etc.) needs the full max-sized buffer rather than just
    /// the fixed header.
    response: VariableSizedBox<UnsafeCell<FSP_FSCTL_TRANSACT_RSP>>,
}

// SAFETY: `VariableSizedBox<T>` is !Send by default because it stores a
// `NonNull<T>`. The pointee is a heap allocation owned exclusively by this
// `AsyncOpCtx`; cross-thread access happens only via owning move
// (`Box<AsyncOpCtx>` is moved into the spawned future, and the TL pointer
// is per-thread, set and cleared inside `InjectOpCtx::poll`).
unsafe impl Send for AsyncFileOperationContext {}

impl AsyncFileOperationContext {
    /// Snapshot the current dispatcher operation context and seed the
    /// framework-owned response with the fixed header that the canonical
    /// WinFSP async pattern installs before
    /// [`FspFileSystemSendResponse`](winfsp_sys::FspFileSystemSendResponse)
    /// (memset 0 + `Size` / `Kind` / `Hint`; see `winfsp/src/dll/fs.c:284`
    /// and the memfs slow-io sample in `winfsp/tst/memfs/memfs.cpp:947`).
    ///
    /// **Must be called on the dispatcher thread**, i.e. inside the
    /// synchronous C callback, before any `await`. Returns `None` if no
    /// operation context is active (which shouldn't happen during a real
    /// callback).
    pub(crate) unsafe fn snapshot(kind: FspTransactKind, hint: u64) -> Option<Box<Self>> {
        let op = unsafe { winfsp_sys::FspFileSystemGetOperationContext().as_ref()? };
        let req_ptr = op.Request;
        if req_ptr.is_null() {
            return None;
        }
        let req_size = unsafe { (*req_ptr).Size as usize };

        let mut request = VariableSizedBox::<FSP_FSCTL_TRANSACT_REQ>::new(req_size);
        // SAFETY: `req_ptr` points at `req_size` bytes of live request data
        // in the dispatcher's buffer (we're still on the dispatcher thread,
        // before any await). The destination box owns `req_size` bytes of
        // zeroed memory aligned to `align_of::<FSP_FSCTL_TRANSACT_REQ>()`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                req_ptr as *const u8,
                request.as_mut_ptr() as *mut u8,
                req_size,
            );
        }

        // `FSP_FSCTL_TRANSACT_RSP` ends in a flex-array `Buffer`. Mirror
        // the dispatcher's own response buffer size so user code is free to
        // grow `response.Size` (up to `FSP_FSCTL_TRANSACT_RSP_SIZEMAX`) and
        // write trailing payload such as reparse data or security
        // descriptors.
        let mut response = VariableSizedBox::<UnsafeCell<FSP_FSCTL_TRANSACT_RSP>>::new(
            crate::constants::FSP_FSCTL_TRANSACT_RSP_SIZEMAX,
        );
        let mut initial_response = FSP_FSCTL_TRANSACT_RSP::default();
        initial_response.Size = std::mem::size_of_val(&initial_response) as u16;
        initial_response.Kind = kind as u32;
        initial_response.Hint = hint;
        // SAFETY: the box owns `FSP_FSCTL_TRANSACT_RSP_SIZEMAX` bytes
        // (≥ `size_of::<FSP_FSCTL_TRANSACT_RSP>()`) aligned to
        // `align_of::<UnsafeCell<FSP_FSCTL_TRANSACT_RSP>>()` (which equals
        // `align_of::<FSP_FSCTL_TRANSACT_RSP>()` since `UnsafeCell<T>` is
        // `#[repr(transparent)]`). Writing the response value through a
        // `*mut FSP_FSCTL_TRANSACT_RSP` cast initialises the fixed header;
        // trailing bytes stay zeroed from the box allocation.
        unsafe {
            std::ptr::write(
                response.as_mut_ptr() as *mut FSP_FSCTL_TRANSACT_RSP,
                initial_response,
            );
        }

        Some(Box::new(AsyncFileOperationContext { request, response }))
    }

    /// Borrow the snapshotted request. Includes the trailing variable
    /// buffer; user code can reach it via the `Buffer` flex-array field
    /// (using its bindgen-generated `as_slice(len)` helper, where `len`
    /// is derived from `Size` minus the fixed header).
    pub(crate) fn request(&self) -> &FSP_FSCTL_TRANSACT_REQ {
        // SAFETY: the box was allocated with `Size` bytes (≥ fixed
        // header size by IRP invariant) and initialised via
        // `copy_nonoverlapping` in `snapshot`.
        unsafe { self.request.as_ref() }
    }

    /// Raw pointer to the response. The caller (`with_operation_response_async`
    /// or the framework's post-await teardown) is responsible for upholding
    /// the usual aliasing rules — but because the response lives behind an
    /// `UnsafeCell` and the only access path is this method, that just
    /// means "don't construct overlapping `&mut`s".
    pub(crate) fn response_mut(&self) -> *mut FSP_FSCTL_TRANSACT_RSP {
        // SAFETY: box owns `FSP_FSCTL_TRANSACT_RSP_SIZEMAX` bytes
        // (≥ `size_of::<FSP_FSCTL_TRANSACT_RSP>()`), with the fixed header
        // initialised in `snapshot`.
        unsafe { self.response.as_ref() }.get()
    }
}

thread_local! {
    /// Per-thread pointer to the currently-polling `AsyncOpCtx`, installed
    /// by [`InjectContextFuture::poll`] and consulted by
    /// [`AsyncFileSystemContext::with_operation_request`] /
    /// [`AsyncFileSystemContext::with_operation_response`] when WinFSP's
    /// own TLS is unset (i.e. the future has moved off the dispatcher
    /// thread).
    pub(crate) static ASYNC_OP_CTX: Cell<Option<NonNull<AsyncFileOperationContext>>> = const { Cell::new(None) };
}

/// Wraps a user future so that on every `poll` it installs the
/// `AsyncOperationContext` into the thread-local and restores it on exit (RAII even
/// against panics).
pub(crate) struct InjectContextFuture<F> {
    inner: F,
    op_ptr: NonNull<AsyncFileOperationContext>,
}

// SAFETY: `op_ptr` references an `AsyncOpCtx` owned by the same async
// block that owns this `InjectOpCtx`. They move together as part of the
// spawned future, so the pointer stays valid through any executor-driven
// thread move.
unsafe impl<F: Send> Send for InjectContextFuture<F> {}

impl<F> InjectContextFuture<F> {
    pub(crate) fn new(inner: F, op_ctx: &AsyncFileOperationContext) -> Self {
        Self {
            inner,
            op_ptr: NonNull::from(op_ctx),
        }
    }
}

impl<F: Future + Unpin> Future for InjectContextFuture<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.as_mut().get_mut();

        // RAII guard so a panic in `inner.poll` can't leave the TL
        // pointing at a stale (or about-to-be-freed) AsyncOpCtx.
        struct Restore(Option<NonNull<AsyncFileOperationContext>>);
        impl Drop for Restore {
            fn drop(&mut self) {
                ASYNC_OP_CTX.set(self.0);
            }
        }

        let prev = ASYNC_OP_CTX.replace(Some(this.op_ptr));
        let _restore = Restore(prev);

        Pin::new(&mut this.inner).poll(cx)
    }
}

// ============================================================================
// Async `unsafe extern "C"` callbacks dispatched by the WinFSP vtable.
// Each one snapshots the dispatcher context, builds an `AsyncOpCtx`, wraps
// the user's future with `InjectOpCtx`, and arranges for
// `FspFileSystemSendResponse` to be called when the future resolves.
// ============================================================================

pub(crate) unsafe extern "C" fn read_directory_async<T: AsyncFileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    pattern: *mut u16,
    marker: *mut u16,
    buffer: PVOID,
    buffer_len: u32,
    bytes_transferred: *mut u32,
) -> FSP_STATUS
where
    <T as FileSystemContext>::FileContext: Sync,
{
    catch_panic!({
        assert_ctx!(fs);
        assert_ctx!(fctx);
        let context: &FileSystemUserContext<T> =
            unsafe { &*(*fs).UserContext.cast::<FileSystemUserContext<T>>() };
        let fctx = unsafe { &*fctx.cast::<T::FileContext>() };

        if !bytes_transferred.is_null() {
            unsafe { bytes_transferred.write(0) }
        }

        // Use the supertrait's TLS-only impl here: we're still on the
        // dispatcher thread (TLS is populated for this IRP), and the
        // injected TL hasn't been installed yet for the spawned future.
        let Some(hint) = (unsafe {
            <T as FileSystemContext>::with_operation_response(context, |resp| resp.Hint)
        }) else {
            return STATUS_TRANSACTION_NOT_FOUND.0;
        };

        return if !buffer.is_null() {
            let fs = AtomicPtr::new(fs);
            // Deep-copy pattern/marker before spawning. The C wrapper at
            // `winfsp/src/dll/fsop.c:1340-1342` aliases these pointers to
            // `Request->Buffer + Offset`, and the dispatcher reuses that
            // buffer for the next IRP as soon as we return STATUS_PENDING
            // — so any `&U16CStr` we captured into the spawned future
            // would dangle.
            let pattern_owned: Option<U16CString> = if !pattern.is_null() {
                Some(unsafe { U16CStr::from_ptr_str(pattern) }.to_ucstring())
            } else {
                None
            };
            let marker_owned: Option<U16CString> = if !marker.is_null() {
                Some(unsafe { U16CStr::from_ptr_str(marker) }.to_ucstring())
            } else {
                None
            };

            let buffer =
                unsafe { std::slice::from_raw_parts_mut(buffer as *mut _, buffer_len as usize) };

            let Some(guard) = context.in_flight.enter() else {
                return STATUS_VOLUME_DISMOUNTED.0;
            };
            // Snapshot the dispatcher's request and seed our own response
            // BEFORE returning STATUS_PENDING. After we return, the
            // dispatcher will reuse its Request/Response buffers for the
            // next IRP, so any TLS pointers would alias unrelated data.
            //
            // SAFETY: We're still on the dispatcher thread inside the C
            // callback; WinFSP's TLS is populated for this IRP.
            let Some(op_ctx) = (unsafe {
                AsyncFileOperationContext::snapshot(
                    FspTransactKind::FspFsctlTransactQueryDirectoryKind,
                    hint,
                )
            }) else {
                return STATUS_TRANSACTION_NOT_FOUND.0;
            };
            let readdir_ft = async move {
                let _guard = guard;
                let user_fut = T::read_directory_async(
                    context,
                    fctx,
                    pattern_owned.as_deref(),
                    DirMarker(marker_owned.as_deref()),
                    buffer,
                );
                let outcome = InjectContextFuture::new(Box::pin(user_fut), &op_ctx).await;

                // SAFETY: `InjectContextFuture` has finished; no thread is still
                // borrowing the response through our TL. We own `op_ctx`.
                let response = unsafe { &mut *op_ctx.response_mut() };
                match outcome {
                    Ok(read) => {
                        response.IoStatus.Status = STATUS_SUCCESS.0 as u32;
                        response.IoStatus.Information = read;
                    }
                    Err(e) => {
                        response.IoStatus.Status = e.to_ntstatus() as u32;
                    }
                }

                unsafe {
                    winfsp_sys::FspFileSystemSendResponse(fs.into_inner(), response);
                }
            };

            context.spawn_task(readdir_ft);
            STATUS_PENDING.0
        } else {
            STATUS_INSUFFICIENT_RESOURCES.0
        }
    })
}

pub(crate) unsafe extern "C" fn read_async<T: AsyncFileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    buffer: PVOID,
    offset: u64,
    length: u32,
    bytes_transferred: *mut u32,
) -> FSP_STATUS
where
    <T as FileSystemContext>::FileContext: Sync,
{
    catch_panic!({
        assert_ctx!(fs);
        assert_ctx!(fctx);
        let context: &FileSystemUserContext<T> =
            unsafe { &*(*fs).UserContext.cast::<FileSystemUserContext<T>>() };
        let fctx = unsafe { &*fctx.cast::<T::FileContext>() };

        if !bytes_transferred.is_null() {
            unsafe { bytes_transferred.write(0) }
        }

        // Use the supertrait's TLS-only impl here: we're still on the
        // dispatcher thread (TLS is populated for this IRP), and the
        // injected TL hasn't been installed yet for the spawned future.
        let Some(hint) = (unsafe {
            <T as FileSystemContext>::with_operation_response(context, |resp| resp.Hint)
        }) else {
            return STATUS_TRANSACTION_NOT_FOUND.0;
        };

        return if !buffer.is_null() {
            let fs = AtomicPtr::new(fs);
            let buffer =
                unsafe { std::slice::from_raw_parts_mut(buffer as *mut u8, length as usize) };
            let Some(guard) = context.in_flight.enter() else {
                return STATUS_VOLUME_DISMOUNTED.0;
            };
            // SAFETY: still on the dispatcher thread; WinFSP TLS is set.
            let Some(op_ctx) = (unsafe {
                AsyncFileOperationContext::snapshot(FspTransactKind::FspFsctlTransactReadKind, hint)
            }) else {
                return STATUS_TRANSACTION_NOT_FOUND.0;
            };
            let read_ft = async move {
                let _guard = guard;
                let user_fut = T::read_async(context, fctx, buffer, offset);
                let outcome = InjectContextFuture::new(Box::pin(user_fut), &op_ctx).await;

                let response = unsafe { &mut *op_ctx.response_mut() };
                match outcome {
                    Ok(read) => {
                        response.IoStatus.Status = STATUS_SUCCESS.0 as u32;
                        response.IoStatus.Information = read;
                    }
                    Err(e) => {
                        response.IoStatus.Status = e.to_ntstatus() as u32;
                    }
                }

                unsafe {
                    winfsp_sys::FspFileSystemSendResponse(fs.into_inner(), response);
                }
            };

            context.spawn_task(read_ft);
            STATUS_PENDING.0
        } else {
            STATUS_INSUFFICIENT_RESOURCES.0
        };
    })
}

pub(crate) unsafe extern "C" fn write_async<T: AsyncFileSystemContext>(
    fs: *mut FSP_FILE_SYSTEM,
    fctx: PVOID,
    buffer: PVOID,
    offset: u64,
    length: u32,
    write_to_eof: u8,
    constrained_io: u8,
    bytes_transferred: *mut u32,
    _out_file_info: *mut FSP_FSCTL_FILE_INFO,
) -> FSP_STATUS
where
    <T as FileSystemContext>::FileContext: Sync,
{
    catch_panic!({
        assert_ctx!(fs);
        assert_ctx!(fctx);

        let context: &FileSystemUserContext<T> =
            unsafe { &*(*fs).UserContext.cast::<FileSystemUserContext<T>>() };
        let fctx = unsafe { &*fctx.cast::<T::FileContext>() };

        if !bytes_transferred.is_null() {
            unsafe { bytes_transferred.write(0) }
        }

        // Use the supertrait's TLS-only impl here: we're still on the
        // dispatcher thread (TLS is populated for this IRP), and the
        // injected TL hasn't been installed yet for the spawned future.
        let Some(hint) = (unsafe {
            <T as FileSystemContext>::with_operation_response(context, |resp| resp.Hint)
        }) else {
            return STATUS_TRANSACTION_NOT_FOUND.0;
        };

        if !buffer.is_null() {
            let buffer =
                unsafe { std::slice::from_raw_parts(buffer as *const u8, length as usize) };
            let fs = AtomicPtr::new(fs);
            let Some(guard) = context.in_flight.enter() else {
                return STATUS_VOLUME_DISMOUNTED.0;
            };
            // SAFETY: still on the dispatcher thread; WinFSP TLS is set.
            let Some(op_ctx) = (unsafe {
                AsyncFileOperationContext::snapshot(
                    FspTransactKind::FspFsctlTransactWriteKind,
                    hint,
                )
            }) else {
                return STATUS_TRANSACTION_NOT_FOUND.0;
            };
            let write_ft = async move {
                let _guard = guard;
                // Hand the user a separately-owned `FileInfo` rather than
                // a `&mut` aliasing `response.Rsp.Write.FileInfo`. Two
                // overlapping `&mut` paths (the captured `&mut FileInfo`
                // and a fresh `&mut FSP_FSCTL_TRANSACT_RSP` obtained via
                // `with_operation_response_async`) would be UB under
                // Stacked Borrows, even though the underlying bytes are
                // the same. We copy into the response struct after the
                // user future has resolved — mirroring the C `memcpy`
                // pattern at `winfsp/src/dll/fsop.c:1063`.
                let mut file_info = FileInfo::default();
                let user_fut = T::write_async(
                    context,
                    fctx,
                    buffer,
                    offset,
                    write_to_eof != 0,
                    constrained_io != 0,
                    &mut file_info,
                );
                let outcome = InjectContextFuture::new(Box::pin(user_fut), &op_ctx).await;

                let response = unsafe { &mut *op_ctx.response_mut() };
                match outcome {
                    Ok(written) => {
                        response.IoStatus.Status = STATUS_SUCCESS.0 as u32;
                        response.IoStatus.Information = written;
                        // SAFETY: `FileInfo` and `FSP_FSCTL_FILE_INFO`
                        // share layout (`ensure_layout!`); the user future
                        // has resolved and dropped its borrow of
                        // `file_info`, so no aliasing reference remains.
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                &file_info as *const FileInfo
                                    as *const FSP_FSCTL_FILE_INFO,
                                &mut response.Rsp.Write.FileInfo,
                                1,
                            );
                        }
                    }
                    Err(e) => {
                        response.IoStatus.Status = e.to_ntstatus() as u32;
                    }
                }

                unsafe {
                    winfsp_sys::FspFileSystemSendResponse(fs.into_inner(), response);
                }
            };

            context.spawn_task(write_ft);

            return STATUS_PENDING.0;
        } else {
            return STATUS_INSUFFICIENT_RESOURCES.0;
        }
    })
}
