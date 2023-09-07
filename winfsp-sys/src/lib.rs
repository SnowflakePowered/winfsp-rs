#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(feature = "docsrs")]
mod bindings;

#[cfg(feature = "docsrs")]
pub use bindings::*;

#[allow(non_camel_case_types)]
pub type FILE_ACCESS_RIGHTS = u32;
#[allow(non_camel_case_types)]
pub type FILE_FLAGS_AND_ATTRIBUTES = u32;
