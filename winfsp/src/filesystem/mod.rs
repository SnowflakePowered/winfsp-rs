//! The main filesystem interfaces and helpers used to implement a WinFSP filesystem.
mod context;
mod directory;
mod host;
mod interface;
mod internals;
mod stream;

mod sealed {
    use crate::filesystem::{directory, host, stream};
    #[doc(hidden)]
    pub trait Sealed {}
    impl<const BUFFER_SIZE: usize> Sealed for directory::DirInfo<BUFFER_SIZE> {}
    impl<const BUFFER_SIZE: usize> Sealed for stream::StreamInfo<BUFFER_SIZE> {}
    impl<const BUFFER_SIZE: usize> Sealed for crate::notify::NotifyInfo<BUFFER_SIZE> {}

    impl Sealed for host::ReadDirectory {}
    impl Sealed for host::GetDirInfoByName {}
}

pub use context::*;
pub use directory::*;
pub use host::*;
pub use internals::*;
pub use stream::*;

#[cfg(feature = "notify")]
pub mod notify;
