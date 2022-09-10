// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
use std::{
    alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout},
    marker::PhantomData,
    mem::{align_of, size_of},
    ptr::{self, NonNull},
};
/// This is a smart pointer type for holding FFI types whose size varies.
/// Most commonly this is with an array member as the last field whose size is specified
/// by either another field, or an external source of information.
pub struct VariableSizedBox<T> {
    size: usize,
    data: NonNull<T>,
    pd: PhantomData<T>,
}
impl<T> VariableSizedBox<T> {
    /// The size is specified in bytes. The data is zeroed.
    pub fn new(size: usize) -> VariableSizedBox<T> {
        if size == 0 {
            return VariableSizedBox::default();
        }
        let layout = Layout::from_size_align(size, align_of::<T>()).unwrap();
        if let Some(data) = NonNull::new(unsafe { alloc_zeroed(layout) }) {
            VariableSizedBox {
                size,
                data: data.cast(),
                pd: PhantomData,
            }
        } else {
            handle_alloc_error(layout)
        }
    }
    /// Use this to get a pointer to pass to FFI functions.
    pub fn as_mut_ptr(&mut self) -> *mut T {
        if self.size == 0 {
            ptr::null_mut()
        } else {
            self.data.as_ptr()
        }
    }
    /// This is used to more safely access the fixed size fields.
    /// # Safety
    /// The current data must be valid for an instance of `T`.
    pub unsafe fn as_ref(&self) -> &T {
        assert!(self.size >= size_of::<T>());
        unsafe { self.data.as_ref() }
    }
}
impl<T> Drop for VariableSizedBox<T> {
    fn drop(&mut self) {
        if self.size == 0 {
            return;
        }
        let layout = Layout::from_size_align(self.size, align_of::<T>()).unwrap();
        unsafe { dealloc(self.as_mut_ptr().cast(), layout) }
    }
}
impl<T> Default for VariableSizedBox<T> {
    fn default() -> Self {
        VariableSizedBox {
            size: 0,
            data: NonNull::dangling(),
            pd: PhantomData,
        }
    }
}
