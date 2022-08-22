use std::env;
use std::path::PathBuf;

fn main() {
    // todo: find from HKLM\SOFTWARE\WOW6432Node\WinFsp;
    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    println!(
        "cargo:rustc-link-search={}",
        project_dir.join("winfsp/lib").to_string_lossy()
    );
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rustc-link-lib=dylib=winfsp-x64");
    println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");

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
        .clang_arg("--include-directory=winfsp/inc")
        .clang_arg("--target=x86_64-pc-windows-msvc")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
