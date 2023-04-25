#[cfg(feature = "system")]
use registry::{Data, Hive, Security};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

static HEADER: &str = r#"
#include <winfsp/winfsp.h>
#include <winfsp/fsctl.h>
#include <winfsp/launch.h>
"#;

#[cfg(not(feature = "system"))]
fn local() -> String {
    let mut lib_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    lib_dir.push("winfsp");
    lib_dir.push("lib");

    println!("cargo:rustc-link-search={}", lib_dir.to_string_lossy());

    format!(
        "--include-directory={}",
        PathBuf::from("winfsp").join("inc").to_string_lossy()
    )
}

#[cfg(feature = "system")]
fn system() -> String {
    let winfsp_install = Hive::LocalMachine
        .open("SOFTWARE\\WOW6432Node\\WinFsp", Security::Read)
        .ok()
        .and_then(|u| u.value("InstallDir").ok())
        .expect("WinFsp installation directory not found.");
    let directory = match winfsp_install {
        Data::String(string) => PathBuf::from(string.to_string_lossy()),
        _ => panic!("unexpected install directory"),
    };

    println!(
        "cargo:rustc-link-search={}",
        directory.join("lib").to_string_lossy()
    );

    format!(
        "--include-directory={}",
        directory.join("inc").to_string_lossy()
    )
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // host needs to be windows
    if cfg!(feature = "docsrs") {
        println!("cargo:warning=WinFSP does not build on any operating system but Windows. This feature is meant for docs.rs only. It will not link when compiled into a binary.");
        File::create(out_dir.join("bindings.rs")).unwrap();
        return;
    }

    if !cfg!(windows) {
        panic!("WinFSP is only supported on Windows.");
    }

    #[cfg(feature = "system")]
    let link_include = system();
    #[cfg(not(feature = "system"))]
    let link_include = local();

    let bindings_path = out_dir.join("bindings.rs");

    if !bindings_path.exists() {
        let gen_h_path = out_dir.join("gen.h");
        let mut gen_h = File::create(&gen_h_path).expect("could not create file");
        gen_h
            .write_all(HEADER.as_bytes())
            .expect("could not write header file");

        let bindings = bindgen::Builder::default()
            .header(gen_h_path.to_str().unwrap())
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

        let bindings = if cfg!(all(target_os = "windows", target_env = "msvc")) {
            println!("cargo:rustc-link-lib=dylib=delayimp");

            if cfg!(target_arch = "x86_64") {
                println!("cargo:rustc-link-lib=dylib=winfsp-x64");
                println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
                bindings.clang_arg("--target=x86_64-pc-windows-msvc")
            } else if cfg!(target_arch = "i686") {
                println!("cargo:rustc-link-lib=dylib=winfsp-x86");
                println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x86.dll");
                bindings.clang_arg("--target=i686-pc-windows-msvc")
            } else if cfg!(target_arch = "aarch64") {
                println!("cargo:rustc-link-lib=dylib=winfsp-a64");
                println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-a64.dll");
                bindings.clang_arg("--target=aarch64-pc-windows-msvc")
            } else {
                panic!("unsupported architecture")
            }
        } else {
            panic!("unsupported triple {}", env::var("TARGET").unwrap())
        };

        bindings
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(bindings_path)
            .expect("Couldn't write bindings!");
    }
}
