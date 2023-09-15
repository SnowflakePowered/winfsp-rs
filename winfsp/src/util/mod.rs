//! Helpful utility wrappers around OS constructs.

#[cfg(feature = "handle-util")]
#[cfg_attr(feature = "docsrs", doc(cfg(feature = "notify")))]
mod handle;

#[cfg(feature = "handle-util")]
#[cfg_attr(feature = "docsrs", doc(cfg(feature = "notify")))]
pub use handle::*;

pub use crate::vsb::VariableSizedBox;
