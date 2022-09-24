# winfsp-rs

[![Latest Version](https://img.shields.io/crates/v/winfsp.svg)](https://crates.io/crates/winfsp) [![Docs](https://docs.rs/winfsp/badge.svg)](https://docs.rs/winfsp) ![License](https://img.shields.io/crates/l/winfsp)

Safe Rust bindings to [WinFSP](https://github.com/winfsp/winfsp) with examples. 

> ⚠️ **Use at your own risk** ⚠️
> 
> A best effort has been made to keep Rust's aliasing rules in mind, and provide a safe and sound wrapper over
> WinFSP. However, FFI with WinFSP involves a lot of pointers that end up as references and the nature of FFI makes
> it difficult to test with miri. While ntptfs is used to test the correctness of the bindings and passes 
> `winfsp-tests-x64.exe --case-insensitive-cmp -volpath_mount_test`, there is still a chance these bindings are unsound.
> 
> Please file a bug report if you encounter unsoundness when using the safe APIs of these bindings.

## Usage
By default, winfsp-rs builds against an included import library. To build against the installed WinFSP libraries, enable the `system`
feature. The path will automatically be determined via the Registry.

```toml
[dependencies.winfsp]
version = "0.4"
features = ["system"]
```
### Delay-loading
To enable delay-loading of WinFSP, add `winfsp` to `build-dependencies` and call `winfsp::build::winfsp_link_delayload()` in
the build script.

#### Cargo.toml
```toml
[build-dependencies]
winfsp = "0.4"
```

#### build.rs
```rust
fn main() { 
    winfsp::build::winfsp_link_delayload();
}
```

### Debugging
Debug output can be enabled with the `debug` feature. Debug output will be written to standard output, 
and redirection of output is not configurable at this time.
```toml
[dependencies.winfsp]
features = ["debug"]
```

## Legal
winfsp-rs is licensed under the terms of the GNU General Public License version 3 as published by the
Free Software Foundation.

### Attribution

> WinFsp - Windows File System Proxy,
> 
> Copyright (C) Bill Zissimopoulos \
> https://github.com/winfsp/winfsp
