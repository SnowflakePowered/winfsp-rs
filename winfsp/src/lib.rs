#![feature(cfg_target_compact)]
#![feature(io_error_more)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod constants;
pub mod filesystem;
mod init;
mod error;
pub mod service;
pub mod util;
mod vsb;

pub use error::Result;
pub use error::FspError;

pub use init::{winfsp_init, winfsp_init_or_die, FspInit};

pub use widestring::{U16CStr as WCStr, U16CString as WCString};

#[cfg(feature = "delayload")]
pub mod build {
    //! Build-time helpers to be called from `build.rs`.
    pub use crate::init::winfsp_link_delayload;
}
