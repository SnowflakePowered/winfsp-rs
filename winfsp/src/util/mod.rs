//! Helpful utility wrappers around OS constructs.

#[cfg(feature = "handle-util")]
#[cfg_attr(feature = "docsrs", doc(cfg(feature = "handle-util")))]
mod handle;

#[cfg(feature = "handle-util")]
#[cfg_attr(feature = "docsrs", doc(cfg(feature = "handle-util")))]
pub use handle::*;

pub use crate::vsb::VariableSizedBox;
