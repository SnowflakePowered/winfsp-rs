#![feature(cfg_target_compact)]
#![feature(io_error_more)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod error;
pub mod filesystem;
mod init;
pub mod service;
pub mod util;
mod vsb;

pub use error::Result;
pub use init::{winfsp_init, winfsp_init_or_die, FspInit};
pub use widestring::{U16CStr as WCStr, U16CString as WCString};

pub mod build {
    pub use crate::init::winfsp_link_delayload;
}
