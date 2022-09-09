#![feature(cfg_target_compact)]

pub fn winfsp_link_delayload() {
    if cfg!(target(os = "windows", arch = "x86_64", env = "msvc")) {
        println!("cargo:rustc-link-lib=dylib=delayimp");
        println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
    } else if cfg!(target(os = "windows", arch = "i686", env = "msvc")) {
        println!("cargo:rustc-link-lib=dylib=delayimp");
        println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x86.dll");
    } else {
        panic!("unsupported triple")
    }
}


fn main() {
    winfsp_link_delayload();
}
