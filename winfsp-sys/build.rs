#![feature(cfg_target_compact)]
use registry::{Data, Hive, Security};
use std::env;
use std::path::PathBuf;

fn local() -> String {
    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    println!(
        "cargo:rustc-link-search={}",
        project_dir.join("winfsp/lib").to_string_lossy()
    );

    "--include-directory=winfsp/inc".into()
}

fn system() -> String {
    let winfsp_install = Hive::LocalMachine
        .open("SOFTWARE\\WOW6432Node\\WinFsp", Security::Read)
        .ok()
        .and_then(|u| u.value("InstallDir").ok())
        .expect("WinFsp installation directory not found.");
    let directory = match winfsp_install {
        Data::String(string) => string.to_string_lossy(),
        _ => panic!("unexpected install directory"),
    };

    println!("cargo:rustc-link-search={}/lib", directory);

    format!("--include-directory={}/inc", directory)
}

fn main() {
    let link_include = if cfg!(feature = "system") {
        system()
    } else {
        local()
    };

    println!("cargo:rerun-if-changed=wrapper.h");

    if cfg!(target(os = "windows", arch = "x86_64", env = "msvc")) {
        println!("cargo:rustc-link-lib=dylib=winfsp-x64");
        println!("cargo:rustc-link-lib=dylib=delayimp");
        println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
    } else if cfg!(target(os = "windows", arch = "i686", env = "msvc")) {
        println!("cargo:rustc-link-lib=dylib=winfsp-x86");
        println!("cargo:rustc-link-lib=dylib=delayimp");
        println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x86.dll");
    } else {
        panic!("unsupported triple")
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .derive_default(true)
        .blocklist_type("_?P?IMAGE_TLS_DIRECTORY.*")
        .allowlist_function("Fsp.*")
        .allowlist_type("FSP.*")
        .allowlist_type("Fsp.*")
        .allowlist_var("FSP_.*")
        .allowlist_var("Fsp.*")
        .allowlist_var("CTL_CODE")
        .clang_arg("-DUNICODE")
        .clang_arg(link_include);

    let bindings = if cfg!(target(os = "windows", arch = "x86_64", env = "msvc")) {
        bindings.clang_arg("--target=x86_64-pc-windows-msvc")
    } else if cfg!(target(os = "windows", arch = "i686", env = "msvc")) {
        bindings.clang_arg("--target=i686-pc-windows-msvc")
    } else {
        panic!("unsupported triple")
    };

    let bindings = bindings
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
