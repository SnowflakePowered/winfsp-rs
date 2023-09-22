//! Helpful utility wrappers around OS constructs.

#[cfg(feature = "handle-util")]
#[cfg_attr(feature = "docsrs", doc(cfg(feature = "handle-util")))]
mod handle;

#[cfg(feature = "handle-util")]
#[cfg_attr(feature = "docsrs", doc(cfg(feature = "handle-util")))]
pub use handle::*;

pub use crate::vsb::VariableSizedBox;

#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct AssertThreadSafe<T>(pub T);

unsafe impl<T> Send for AssertThreadSafe<T> {}

unsafe impl<T> Sync for AssertThreadSafe<T> {}
