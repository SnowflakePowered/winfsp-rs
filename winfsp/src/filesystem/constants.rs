use winfsp_sys::WCHAR;

pub use winfsp_sys::FSP_FSCTL_DEFAULT_ALIGNMENT;
pub use winfsp_sys::FSP_FSCTL_DEVICECONTROL_SIZEMAX;
pub use winfsp_sys::FSP_FSCTL_TRANSACT_BATCH_BUFFER_SIZEMIN;
pub use winfsp_sys::FSP_FSCTL_TRANSACT_BUFFER_SIZEMIN;
pub use winfsp_sys::FSP_FSCTL_TRANSACT_REQ_SIZEMAX;
pub use winfsp_sys::FSP_FSCTL_TRANSACT_RSP_SIZEMAX;

pub const FSP_FSCTL_TRANSACT_PATH_SIZEMAX: u32 = (1024 * std::mem::size_of::<WCHAR>()) as u32;
