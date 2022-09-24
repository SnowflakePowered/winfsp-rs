use std::alloc::Layout;

mod fileinfo;
mod volumeinfo;
pub(crate) mod widenameinfo;

pub use fileinfo::*;
pub use volumeinfo::*;
pub use widenameinfo::WideNameInfo;

#[allow(dead_code)]
pub(crate) const fn assert_layout<T, J>() -> bool {
    let a = Layout::new::<T>();
    let b = Layout::new::<J>();
    a.size() == b.size() && b.align() == b.align()
}

macro_rules! ensure_layout {
    ($t:ty, $j:ty) => {
        static_assertions::assert_eq_align!($t, $j);
        static_assertions::assert_eq_size!($t, $j);
        static_assertions::const_assert!(crate::filesystem::assert_layout::<$t, $j>());
    };
}

pub(crate) use ensure_layout;
