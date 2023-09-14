# winfsp-rs

[![Latest Version](https://img.shields.io/crates/v/winfsp.svg)](https://crates.io/crates/winfsp) [![Docs](https://docs.rs/winfsp/badge.svg)](https://docs.rs/winfsp) ![License](https://img.shields.io/crates/l/winfsp)

Safe Rust bindings to [WinFSP](https://github.com/winfsp/winfsp) with examples. 

> ⚠️ **Use at your own risk** ⚠️
> 
> A best effort has been made to keep Rust's aliasing rules in mind, and provide a safe and sound wrapper over
> WinFSP. However, FFI with WinFSP involves a lot of pointers that end up as references and the nature of FFI makes
> it difficult to test with miri. While ntptfs is used to test the correctness of the bindings,
> there is still a chance these bindings are unsound.
> 
> Please file a bug report if you encounter unsoundness when using the safe APIs of these bindings.

## Usage
By default, winfsp-rs builds against an included import library. To build against the installed WinFSP libraries, enable the `system`
feature. The path will automatically be determined via the Registry.

```toml
[dependencies.winfsp]
version = "0.8"
features = ["system"]
```
### Delay-loading
To enable delay-loading of WinFSP, add `winfsp` to `build-dependencies` and call `winfsp::build::winfsp_link_delayload()` in
the build script. This is required for winfsp-rs.

#### Cargo.toml
```toml
[build-dependencies]
winfsp = "0.8"
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
### Building on Stable Rust
It is recommended you build winfsp-rs on nightly Rust as it relies on [`io_error_more`](https://github.com/rust-lang/rust/issues/86442)
and [`strict_provenance`](https://github.com/rust-lang/rust/issues/95228). However, it is possible to build winfsp-rs
on stable Rust without support for these features. 

```toml
[dependencies.winfsp]
default-features = false
# notify if you need filesystem notifications, delayload is needed for build-time helpers.
features = ["notify", "delayload"]
```


## Testing
`ntptfs-winfsp-rs`, a port of `ntptfs` to `winfsp-rs` is used to test the bindings. It passes all tests that `ntptfs`
passes at the same elevation level.

<details>
<summary>Test results</summary>

```
❯ F:\winfsp-tests-x64 --external --resilient +* --case-insensitive-cmp -delete_access_test -getfileattr_test -exec_rename_dir_test -rename_flipflop_test -stream_rename_flipflop_test -stream_getstreaminfo_test -ea*
create_test............................ OK 0.02s
create_fileattr_test................... OK 0.01s
create_readonlydir_test................ OK 0.01s
create_related_test.................... OK 0.00s
create_allocation_test................. OK 0.01s
create_sd_test......................... OK 0.01s
create_notraverse_test................. OK 0.00s
create_backup_test..................... OK 0.00s
create_restore_test.................... OK 0.00s
create_share_test...................... OK 0.01s
create_curdir_test..................... OK 0.00s
create_namelen_test.................... OK 0.01s
getfileinfo_test....................... OK 0.00s
getfileinfo_name_test.................. OK 0.00s
setfileinfo_test....................... OK 0.00s
delete_test............................ OK 0.00s
delete_pending_test.................... OK 0.00s
delete_mmap_test....................... OK 0.00s
delete_standby_test.................... OK 0.07s
delete_ex_test......................... OK 0.01s
rename_test............................ OK 0.02s
rename_backslash_test.................. OK 0.01s
rename_open_test....................... OK 0.00s
rename_caseins_test.................... OK 0.01s
rename_mmap_test....................... OK 0.01s
rename_standby_test.................... OK 0.15s
rename_ex_test......................... OK 0.01s
getvolinfo_test........................ OK 0.00s
setvolinfo_test........................ OK 0.00s
getsecurity_test....................... OK 0.00s
setsecurity_test....................... OK 0.00s
security_stress_meta_test.............. OK 0.24s
rdwr_noncached_test.................... OK 0.02s
rdwr_noncached_overlapped_test......... OK 0.02s
rdwr_cached_test....................... OK 0.02s
rdwr_cached_append_test................ OK 0.01s
rdwr_cached_overlapped_test............ OK 0.02s
rdwr_writethru_test.................... OK 0.01s
rdwr_writethru_append_test............. OK 0.01s
rdwr_writethru_overlapped_test......... OK 0.01s
rdwr_mmap_test......................... OK 0.15s
rdwr_mixed_test........................ OK 0.01s
flush_test............................. OK 0.05s
flush_volume_test...................... OK 0.00s
lock_noncached_test.................... OK 0.02s
lock_noncached_overlapped_test......... OK 0.01s
lock_cached_test....................... OK 0.01s
lock_cached_overlapped_test............ OK 0.01s
querydir_test.......................... OK 0.64s
querydir_nodup_test.................... OK 4.43s
querydir_single_test................... OK 1.78s
querydir_expire_cache_test............. OK 0.00s
querydir_buffer_overflow_test.......... OK 0.00s
querydir_namelen_test.................. OK 0.01s
dirnotify_test......................... OK 1.01s
exec_test.............................. OK 0.02s
exec_delete_test....................... OK 1.03s
exec_rename_test....................... OK 1.03s
reparse_guid_test...................... OK 4.83s
reparse_nfs_test....................... OK 0.00s
reparse_symlink_test................... OK 0.01s
reparse_symlink_relative_test.......... OK 0.04s
stream_create_test..................... OK 0.02s
stream_create_overwrite_test........... OK 0.01s
stream_create_related_test............. OK 0.00s
stream_create_sd_test.................. OK 0.00s
stream_create_share_test............... OK 0.03s
stream_getfileinfo_test................ OK 0.00s
stream_setfileinfo_test................ OK 0.01s
stream_delete_test..................... OK 0.01s
stream_delete_pending_test............. OK 0.01s
stream_getsecurity_test................ OK 0.00s
stream_setsecurity_test................ OK 0.00s
stream_getstreaminfo_expire_cache_test. OK 0.00s
stream_dirnotify_test.................. OK 1.01s
oplock_level1_test..................... OK 1.31s
oplock_level2_test..................... OK 2.48s
oplock_batch_test...................... OK 1.25s
oplock_filter_test..................... OK 1.24s
oplock_rwh_test........................ OK 1.24s
oplock_rw_test......................... OK 1.24s
oplock_rh_test......................... OK 2.48s
oplock_r_test.......................... OK 2.48s
oplock_not_granted_test................ OK 0.00s
wsl_stat_test.......................... OK 0.00s
--- COMPLETE ---
```

</details>

## Legal
winfsp-rs is licensed under the terms of the GNU General Public License version 3 as published by the
Free Software Foundation.

### Attribution

> WinFsp - Windows File System Proxy,
> 
> Copyright (C) Bill Zissimopoulos \
> https://github.com/winfsp/winfsp
