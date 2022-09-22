# winfsp-sys

[![Latest Version](https://img.shields.io/crates/v/winfsp-sys.svg)](https://crates.io/crates/winfsp-sys) [![Docs](https://docs.rs/winfsp-sys/badge.svg)](https://docs.rs/winfsp-sys) ![License](https://img.shields.io/crates/l/winfsp-sys)


Raw FFI bindings to [WinFSP](https://github.com/winfsp/winfsp). 

## Usage
The [winfsp-rs](https://crates.io/crates/winfsp-rs) crates provides idiomatic wrappers around the raw WinFSP APIs. 

By default, winfsp-sys builds against an included import library. To build against the installed WinFSP libraries, enable the `system`
feature. The path will automatically be determined via the Registry.

```toml
[dependencies.winfsp-sys]
version = 0.1
features = ["system"]
```