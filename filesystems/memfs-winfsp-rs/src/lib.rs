#![deny(unsafe_op_in_unsafe_fn)]
//! memfs port from WinFSP
//!
//! This is entirely vibecoded and should only be used as a reference.
mod ea;
pub mod memfs;
mod path;
mod slowio;

pub use memfs::{MemFs, MemFsContext, MemFsFlags, MemFsParams};
