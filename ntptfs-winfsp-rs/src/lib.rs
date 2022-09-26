#![feature(strict_provenance)]
#![feature(io_error_more)]
#![feature(let_chains)]
#![deny(unsafe_op_in_unsafe_fn)]

mod fs;
mod native;

pub use fs::context::NtPassthroughContext;
pub use fs::ntptfs::NtPassthroughFilesystem;
pub use fs::file::NtPassthroughFile;