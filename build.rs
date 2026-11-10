// On 32-bit Windows (MSVC) the original rw_data.dll exports its functions under their
// decorated __stdcall names (`_dtaOpen@8`, ...) with fixed ordinals, and the game imports
// them that way. rustc exports `#[no_mangle]` functions under their plain names, so the
// decorated names and the ordinals are added here as extra linker exports (the plain
// names stay exported too, which does no harm).
//
// Every other target (64-bit Windows, Linux, macOS, ...) has no name decoration and uses
// the plain names only.

/// (decorated name, ordinal) of every export of the original DLL.
const EXPORTS: &[(&str, u32)] = &[
    ("_dtaAddDir@8", 1),
    ("_dtaAddExtension@8", 2),
    ("_dtaAddFQLExtensionFilter@4", 3),
    ("_dtaBin2Text@8", 4),
    ("_dtaClearFQLExtensionFilter@0", 5),
    ("_dtaClose@4", 6),
    ("_dtaCloseFQL@0", 7),
    ("_dtaCloseFileLog@4", 8),
    ("_dtaCreate@4", 9),
    ("_dtaCreateFQL@4", 10),
    ("_dtaDelete@4", 11),
    ("_dtaDumpMemoryLeaks@4", 12),
    ("_dtaFQLBegin@4", 13),
    ("_dtaFQLEnd@0", 14),
    ("_dtaFlush@4", 15),
    ("_dtaGetPackDirectAccess@8", 16),
    ("_dtaGetTime@12", 17),
    ("_dtaOpen@8", 18),
    ("_dtaOpenFileLog@8", 19),
    ("_dtaOpenWrite@8", 20),
    ("_dtaRead@12", 21),
    ("_dtaSeek@12", 22),
    ("_dtaSetCallbackERR@4", 23),
    ("_dtaSetDebugFQLExt@4", 24),
    ("_dtaSetPathBeforeLogItems@8", 25),
    ("_dtaWrite@12", 26),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if arch == "x86" && os == "windows" && env == "msvc" {
        for (name, ordinal) in EXPORTS {
            println!("cargo:rustc-cdylib-link-arg=/EXPORT:{name},@{ordinal}");
        }
        // rustc lists the same names (without ordinals) in its own export file; the
        // linker keeps the first specification, the one above, and says so.
        println!("cargo:rustc-cdylib-link-arg=/IGNORE:4197");
    }
}
