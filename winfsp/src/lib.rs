#![cfg_attr(feature = "docsrs", feature(doc_cfg))]
#![deny(unsafe_op_in_unsafe_fn)]
#![forbid(missing_docs)]

//! Safe Rust bindings to [WinFSP](https://github.com/winfsp/winfsp).
//!
//! ## Usage
//! The `winfsp` crate wraps the WinFSP service architecture and user mode filesystem host.
//! Implement the [`FileSystemContext`](crate::filesystem::FileSystemContext) trait, then
//! create a [`FileSystemHost`](crate::host::FileSystemHost) instance.
//!
//! It is highly recommended to use the service architecture to manage the lifecycle of a `FileSystemHost`.
//!
//! Using [`FileSystemServiceBuilder`](crate::service::FileSystemServiceBuilder), create, start, and mount the `FileSystemHost`
//! within the [`FileSystemServiceBuilder::with_start`](crate::service::FileSystemServiceBuilder::with_start) closure,
//! and handle teardown in the [`FileSystemServiceBuilder::with_stop`](crate::service::FileSystemServiceBuilder::with_stop)
//! closure.
//!
//! The resulting service can be built after initializing WinFSP for your application with [`winfsp_init`](crate::winfsp_init) or [`winfsp_init_or_die`](crate::winfsp_init_or_die).
//!
//! ## Build-time requirements
//! WinFSP only supports delayloading of its library. You must emit the required
//! compile flags in `build.rs` with [`winfsp_link_delayload`](crate::build::winfsp_link_delayload).
//!
//! ```rust
//! fn main() {
//!     winfsp::build::winfsp_link_delayload();
//! }
//! ```
//!
pub mod constants;
mod error;
pub mod filesystem;
pub mod host;
mod init;
pub mod service;
pub mod util;
mod vsb;

#[cfg(feature = "notify")]
#[cfg_attr(feature = "docsrs", doc(cfg(feature = "notify")))]
pub mod notify;

// only publicly export notify if feature is enabled.
#[cfg(not(feature = "notify"))]
mod notify;

pub use error::FspError;
pub use error::Result;

pub use init::{FspInit, winfsp_init, winfsp_init_or_die};

pub use widestring::{U16CStr, U16CString};

#[cfg(feature = "delayload")]
#[cfg_attr(feature = "docsrs", doc(cfg(feature = "build")))]
pub mod build {
    //! Build-time helpers to be called from `build.rs`.
    pub use crate::init::winfsp_link_delayload;
}
