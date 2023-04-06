#[cfg(feature = "system")]
use registry::{Data, Hive, Security};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

const HEADER: &str = r#"
#include <winfsp/winfsp.h>
#include <winfsp/fsctl.h>
#include <winfsp/launch.h>
"#;

#[cfg(not(feature = "system"))]
fn local() -> String {
    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    println!(
        "cargo:rustc-link-search={}",
        project_dir.join("winfsp/lib").to_string_lossy()
    );

    "--include-directory=winfsp/inc".into()
}

#[cfg(feature = "system")]
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

    println!("cargo:rustc-link-lib=dylib=delayimp");

    if cfg!(all(
        target_os = "windows",
        target_arch = "x86_64",
        target_env = "msvc"
    )) {
        println!("cargo:rustc-link-lib=dylib=winfsp-x64");
        println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
    } else if cfg!(all(
        target_os = "windows",
        target_arch = "i686",
        target_env = "msvc"
    )) {
        println!("cargo:rustc-link-lib=dylib=winfsp-x86");
        println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x86.dll");
    } else {
        panic!("unsupported triple {}", env::var("TARGET").unwrap())
    }

    let bindings_path_str = out_dir.join("bindings.rs");

    if !Path::new(&bindings_path_str).exists() {
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

        let bindings = if cfg!(target_os = "windows")
            && cfg!(target_arch = "x86_64")
            && cfg!(target_env = "msvc")
        {
            bindings.clang_arg("--target=x86_64-pc-windows-msvc")
        } else if cfg!(target_os = "windows")
            && cfg!(target_arch = "i686")
            && cfg!(target_env = "msvc")
        {
            bindings.clang_arg("--target=i686-pc-windows-msvc")
        } else {
            panic!("unsupported triple {}", env::var("TARGET").unwrap())
        };

        let bindings = bindings
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("Unable to generate bindings");

        bindings
            .write_to_file(out_dir.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
