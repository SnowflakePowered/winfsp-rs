
// todo: safe wrappers
pub use winfsp_sys::{FSP_FSCTL_FILE_INFO, FSP_FSCTL_OPEN_FILE_INFO, FSP_FSCTL_VOLUME_INFO};

mod widenameinfo;

pub use widenameinfo::*;