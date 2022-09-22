mod context;
mod directory;
mod host;
mod interface;
mod internals;
mod notify;
mod stream;

mod sealed {
    use crate::filesystem::{directory, notify, stream};
    #[doc(hidden)]
    pub trait Sealed {}
    impl<const BUFFER_SIZE: usize> Sealed for directory::DirInfo<BUFFER_SIZE> {}
    impl<const BUFFER_SIZE: usize> Sealed for stream::StreamInfo<BUFFER_SIZE> {}
    impl<const BUFFER_SIZE: usize> Sealed for notify::NotifyInfo<BUFFER_SIZE> {}
}

pub use context::*;
pub use directory::*;
pub use host::*;
pub use internals::*;
pub use notify::*;
pub use stream::*;
