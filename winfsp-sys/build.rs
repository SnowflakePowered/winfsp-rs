use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(feature = "system")]
use windows_registry::LOCAL_MACHINE;

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

    // 32-bit installers land in WOW6432Node; ARM64 native installers
    // write directly under SOFTWARE. Try both so that an ARM64 host
    // with a native WinFsp install still resolves headers + libs.
    let directory = ["SOFTWARE\\WOW6432Node\\WinFsp", "SOFTWARE\\WinFsp"]
        .iter()
        .find_map(|p| {
            LOCAL_MACHINE
                .open(p)
                .ok()
                .and_then(|u| u.get_string("InstallDir").ok())
        })
        .expect("WinFsp installation directory not found.");

    println!("cargo:rustc-link-search={}/lib", directory);

    format!("--include-directory={}/inc", directory)
}

fn copy_winfsp_dll(winfsp_lib: &str) {
    println!("cargo:rerun-if-env-changed=WINFSP_DLL_OUTPUT_PATH");

    // Get the output path from environment variable
    let dll_out_path = match env::var("WINFSP_DLL_OUTPUT_PATH") {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            return;
        }
    };

    if let Err(e) = fs::create_dir_all(&dll_out_path) {
        panic!(
            "Failed to create WinFSP DLL output directory {}: {}",
            dll_out_path.display(),
            e
        );
    }

    let project_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let dll_path = project_dir
        .join("winfsp/bin")
        .join(format!("{}.dll", winfsp_lib));
    if !dll_path.exists() {
        panic!(
            "WinFSP DLL source file does not exist: {}",
            dll_path.display()
        );
    }

    let dll_dest = dll_out_path.join(format!("{}.dll", winfsp_lib));
    if let Err(e) = fs::copy(&dll_path, &dll_dest) {
        panic!(
            "Failed to copy {} to {}: {}",
            dll_path.display(),
            dll_dest.display(),
            e
        );
    }
}

/// Linkage environment for the active target.
///
/// WinFSP ships MSVC-format `.lib` import libraries; both classic MSVC
/// and `*-pc-windows-gnullvm` consume them through `lld-link`, so the
/// link decisions are nearly identical between the two — but the clang
/// `--target`, the delay-load syntax, and whether we ask rustc for
/// `delayimp` all diverge, so we keep them as distinct cases.
#[derive(Copy, Clone, PartialEq, Eq)]
enum LinkEnv {
    Msvc,
    GnuLlvm,
}

impl LinkEnv {
    fn detect(target_env: &str, target_abi: &str) -> Option<Self> {
        match (target_env, target_abi) {
            ("msvc", _) => Some(Self::Msvc),
            ("gnu", "llvm") => Some(Self::GnuLlvm),
            _ => None,
        }
    }

    fn clang_target(self, target_arch: &str) -> Option<&'static str> {
        Some(match (self, target_arch) {
            (Self::Msvc, "x86_64") => "x86_64-pc-windows-msvc",
            (Self::Msvc, "x86") => "x86-pc-windows-msvc",
            (Self::Msvc, "aarch64") => "aarch64-pc-windows-msvc",
            (Self::GnuLlvm, "x86_64") => "x86_64-w64-mingw32",
            (Self::GnuLlvm, "x86") => "i686-w64-mingw32",
            (Self::GnuLlvm, "aarch64") => "aarch64-w64-mingw32",
            _ => return None,
        })
    }
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
    let target_abi = env::var("CARGO_CFG_TARGET_ABI").unwrap_or_default();

    if target_os != "windows" {
        panic!("WinFSP is only supported on Windows.");
    }

    let link_env = LinkEnv::detect(&target_env, &target_abi)
        .unwrap_or_else(|| panic!("unsupported triple {}", env::var("TARGET").unwrap()));

    #[cfg(feature = "system")]
    let link_include = system();
    #[cfg(not(feature = "system"))]
    let link_include = local();

    let winfsp_lib = match target_arch.as_str() {
        "x86_64" => "winfsp-x64",
        "x86" => "winfsp-x86",
        "aarch64" => "winfsp-a64",
        _ => panic!("unsupported triple {}", env::var("TARGET").unwrap()),
    };
    let clang_target = link_env
        .clang_target(&target_arch)
        .unwrap_or_else(|| panic!("unsupported triple {}", env::var("TARGET").unwrap()));

    println!("cargo:rustc-link-lib=dylib={}", winfsp_lib);
    match link_env {
        LinkEnv::Msvc => {
            // delayimp.lib provides __delayLoadHelper2 under MSVC.
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:{}.dll", winfsp_lib);
        }
        LinkEnv::GnuLlvm => {
            // LLVM-MinGW's libdelayimp.a isn't on rustc's link search
            // path by default; lld-link's --delayload lowering provides
            // the helper itself, and ld.lld in mingw mode requires the
            // GNU-style flag rather than MSVC's `/DELAYLOAD:`.
            println!("cargo:rustc-link-arg=-Wl,--delayload={}.dll", winfsp_lib);
        }
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

        let bindings = bindings.clang_arg(&format!("--target={}", clang_target));

        // Under mingw/llvm-mingw clang defaults to C99, which rejects the
        // `static_assert(e,m)` MSVC C extension used in winfsp/fsctl.h.
        // C11 has it via <assert.h> macro mapping; ensure that mode + the
        // standard headers are pulled in.
        let bindings = match link_env {
            LinkEnv::GnuLlvm => bindings
                .clang_arg("-std=c11")
                .clang_arg("-include")
                .clang_arg("assert.h"),
            LinkEnv::Msvc => bindings,
        };

        let bindings = bindings
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .expect("Unable to generate bindings");

        bindings
            .write_to_file(out_dir.join("bindings.rs"))
            .expect("Couldn't write bindings!");
    }

    #[cfg(not(feature = "system"))]
    copy_winfsp_dll(winfsp_lib);
}
