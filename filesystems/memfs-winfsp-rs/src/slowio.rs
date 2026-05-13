//! Optional "slow I/O" delays applied to `read`, `write`, and `read_directory`
//! when the file system is configured with a non-zero
//! [`MemFsParams::slowio_max_delay`](crate::memfs::MemFsParams).
//!
//! Mirrors the `MEMFS_SLOWIO` machinery in `memfs.cpp`. In the C reference
//! implementation each "slow" operation either snoozes synchronously on the
//! dispatcher thread or spawns a worker thread and returns `STATUS_PENDING`;
//! once the worker finishes it calls `FspFileSystemSendResponse` directly.
//!
//! Here we let winfsp-rs's [`AsyncFileSystemContext`] do that plumbing:
//! every async I/O callback runs on a tokio runtime, returns
//! `STATUS_PENDING` to WinFSP through the async vtable, and the framework
//! takes care of `SendResponse` when the future resolves. We just await a
//! tokio sleep before delegating to the synchronous implementation.

use rand::Rng;
use std::time::Duration;

pub struct Slowio {
    pub max_delay: u32,
    pub percent_delay: u32,
    pub rarefy_delay: u32,
}

impl Slowio {
    pub fn new(max_delay: u32, percent_delay: u32, rarefy_delay: u32) -> Self {
        Self {
            max_delay,
            percent_delay,
            rarefy_delay,
        }
    }

    /// Sleep for a pseudo-random number of milliseconds derived from the
    /// configured max-delay / rarefy parameters. Returns immediately when
    /// `max_delay == 0`.
    ///
    /// `percent_delay` gates whether the delay applies on a per-call basis,
    /// allowing tests to interleave "fast" and "slow" calls (matching the
    /// purpose of `SlowioReturnPending` in the C reference; whether the
    /// kernel sees STATUS_PENDING is decided by the async vtable, not by us).
    pub async fn snooze(&self) {
        if self.max_delay == 0 {
            return;
        }
        // Scope the (!Send) ThreadRng so the resulting future stays Send.
        let millis = {
            let mut rng = rand::rng();
            if self.percent_delay < 100 && rng.random_range(0..100) >= self.percent_delay {
                return;
            }
            let max = rng.random_range(0..=self.max_delay);
            let shift = rng.random_range(0..=self.rarefy_delay);
            (max as u64) >> shift
        };
        if millis > 0 {
            tokio::time::sleep(Duration::from_millis(millis)).await;
        }
    }
}
