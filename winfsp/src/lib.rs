#![feature(cfg_target_compact)]
#![feature(io_error_more)]
#![feature(ptr_const_cast)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod constants;
mod error;
pub mod filesystem;
mod init;
pub mod service;
pub mod util;
mod vsb;

#[cfg(feature = "notify")]
pub mod notify;

pub use error::FspError;
pub use error::Result;

pub use init::{winfsp_init, winfsp_init_or_die, FspInit};

pub use widestring::{U16CStr as WCStr, U16CString as WCString};

#[cfg(feature = "delayload")]
pub mod build {
    //! Build-time helpers to be called from `build.rs`.
    pub use crate::init::winfsp_link_delayload;
}
