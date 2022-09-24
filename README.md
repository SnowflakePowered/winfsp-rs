# winfsp-rs

[![Latest Version](https://img.shields.io/crates/v/winfsp.svg)](https://crates.io/crates/winfsp) [![Docs](https://docs.rs/winfsp/badge.svg)](https://docs.rs/winfsp) ![License](https://img.shields.io/crates/l/winfsp)

Safe Rust bindings to [WinFSP](https://github.com/winfsp/winfsp) with examples. 

> ⚠️ **Very WIP and not production ready!** ⚠️
> 
> This crate is possibly unsound, and is very undocumented.   
> A best effort has been made to keep aliasing rules around, but FFI with WinFSP involves a lot of pointers that end up 
> as references when putting a Rust-friendly API around it, and the nature of FFI makes it difficult to test with miri.

## Usage
By default, winfsp-rs builds against an included import library. To build against the installed WinFSP libraries, enable the `system`
feature. The path will automatically be determined via the Registry.

```toml
[dependencies.winfsp]
version = "0.3"
features = ["system"]
```
### Delay-loading
To enable delay-loading of WinFSP, add `winfsp` to `build-dependencies` and call `winfsp::build::winfsp_link_delayload()` in
the build script.

#### Cargo.toml
```toml
[build-dependencies]
winfsp = "0.3"
```

#### build.rs
```rust
fn main() { 
    winfsp::build::winfsp_link_delayload();
}
```

### Debugging
Debug output can be enabled with the `debug` feature. Debug output is not currently configurable at runtime.
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
