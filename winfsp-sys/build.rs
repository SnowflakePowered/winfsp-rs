use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(feature = "system")]
use windows_registry::{Value, LOCAL_MACHINE};

static HEADER: &str = r#"
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
    if !cfg!(windows) {
        panic!("'system' feature not supported for cross-platform compilation.");
    }

    let winfsp_install = LOCAL_MACHINE
        .open("SOFTWARE\\WOW6432Node\\WinFsp")
        .ok()
        .and_then(|u| u.get_value("InstallDir").ok())
        .expect("WinFsp installation directory not found.");
    let directory = match winfsp_install {
        Value::String(string) => string,
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

    // Use the target OS configuration instead of the host OS configuration to enable cross-platform compilation
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string());
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string());
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_else(|_| "unknown".to_string());

    if target_os != "windows" {
        panic!("WinFSP is only supported on Windows.");
    }

    #[cfg(feature = "system")]
    let link_include = system();
    #[cfg(not(feature = "system"))]
    let link_include = local();

    println!("cargo:rustc-link-lib=dylib=delayimp");

    // Architecture-specific configuration
    let (winfsp_lib, clang_target) = match (target_arch.as_str(), target_env.as_str()) {
        ("x86_64", "msvc") => ("winfsp-x64", "x86_64-pc-windows-msvc"),
        ("x86", "msvc") => ("winfsp-x86", "x86-pc-windows-msvc"),
        ("aarch64", "msvc") => ("winfsp-a64", "aarch64-pc-windows-msvc"),
        _ => panic!("unsupported triple {}", env::var("TARGET").unwrap()),
    };

    println!("cargo:rustc-link-lib=dylib={}", winfsp_lib);
    println!("cargo:rustc-link-arg=/DELAYLOAD:{}.dll", winfsp_lib);

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

        let bindings = bindings.clang_arg(&format!("--target={}", clang_target));

        let bindings = bindings
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("Unable to generate bindings");

        bindings
            .write_to_file(out_dir.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
