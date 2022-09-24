//! The main filesystem interfaces and helpers used to implement a WinFSP filesystem.
mod context;
mod directory;
mod host;
mod interface;
mod internals;
mod stream;
mod volume;

mod sealed {
    use crate::filesystem::{directory, stream};
    #[doc(hidden)]
    pub trait Sealed {}
    impl<const BUFFER_SIZE: usize> Sealed for directory::DirInfo<BUFFER_SIZE> {}
    impl<const BUFFER_SIZE: usize> Sealed for stream::StreamInfo<BUFFER_SIZE> {}
    impl<const BUFFER_SIZE: usize> Sealed for crate::notify::NotifyInfo<BUFFER_SIZE> {}

    pub use super::internals::widenameinfo::WideNameInfoInternal;
}

pub use context::*;
pub use directory::*;
pub use host::*;
pub use internals::*;
pub use stream::*;
pub use volume::*;
