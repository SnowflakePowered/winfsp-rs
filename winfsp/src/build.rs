//! Build-time helpers to be called from `build.rs`.

/// Linkage environment for the active build target.
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
}

/// Build-time helper to enable `DELAYLOAD` linking to the system WinFSP.
///
/// This function should be called from `build.rs`. Reads target config
/// from cargo env vars so cross-compiled build scripts work correctly.
pub fn winfsp_link_delayload() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_abi = std::env::var("CARGO_CFG_TARGET_ABI").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_os != "windows" {
        panic!("unsupported triple");
    }
    let link_env =
        LinkEnv::detect(&target_env, &target_abi).unwrap_or_else(|| panic!("unsupported triple"));

    let dll = match target_arch.as_str() {
        "x86_64" => "winfsp-x64.dll",
        "x86" => "winfsp-x86.dll",
        "aarch64" => "winfsp-a64.dll",
        _ => panic!("unsupported architecture"),
    };

    match link_env {
        LinkEnv::Msvc => {
            println!("cargo:rustc-link-lib=dylib=delayimp");
            println!("cargo:rustc-link-arg=/DELAYLOAD:{dll}");
        }
        LinkEnv::GnuLlvm => {
            // LLVM-MinGW's libdelayimp.a isn't on rustc's link search
            // path by default; lld-link's --delayload lowering provides
            // the helper itself, and ld.lld in mingw mode requires the
            // GNU-style flag rather than MSVC's `/DELAYLOAD:`.
            println!("cargo:rustc-link-arg=-Wl,--delayload={dll}");
        }
    }
}
