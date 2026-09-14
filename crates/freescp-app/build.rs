use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Each .slint file is compiled separately to OUT_DIR/<module>.rs. Since
    // slint_build::compile's SLINT_INCLUDE_GENERATED env var can only carry
    // ONE generated file, we aggregate all of them into OUT_DIR/modules.rs
    // ourselves: each wrapper module includes the generated file and
    // re-exports its types, so main.rs can reference them as
    // crate::ui::main_window::*, crate::ui::connection_dialog::*, etc.
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));

    embed_windows_resources(&manifest);

    // (input file, rust module name, internal module declared by the
    // generated file). The internal name comes from the last `export
    // component` in each file; update it if exports change.
    let files: &[(&str, &str, &str)] = &[
        (
            "main-window.slint",
            "main_window",
            "slint_generatedMainWindow",
        ),
        (
            "connection-dialog.slint",
            "connection_dialog",
            "slint_generatedConnectionDialog",
        ),
        (
            "transfer-queue.slint",
            "transfer_queue",
            "slint_generatedTransferQueueDialog",
        ),
        (
            "site-manager.slint",
            "site_manager",
            "slint_generatedSiteManagerDialog",
        ),
        (
            "settings.slint",
            "settings",
            "slint_generatedSettingsDialog",
        ),
        ("about.slint", "about", "slint_generatedAboutDialog"),
        (
            "permissions.slint",
            "permissions",
            "slint_generatedPermissionsDialog",
        ),
        (
            "overwrite-dialog.slint",
            "overwrite_dialog",
            "slint_generatedOverwriteDialog",
        ),
        // Test-only wrapper around ConsoleView (used by
        // src/console_view_tests.rs); unlike console.slint it inherits Window,
        // so it can be compiled as an entry file.
        (
            "console-test.slint",
            "console_test",
            "slint_generatedConsoleTestWindow",
        ),
        // NOTE: ui/console.slint is imported by main-window.slint (and
        // re-exported there) instead of being compiled on its own: it exports
        // no Window, which slint_build warns about for entry files.
    ];

    // Test-only modules are never instantiated outside #[cfg(test)] code, so
    // silence dead-code warnings for them in regular builds.
    let test_only = ["console-test.slint"];

    let mut wrapper = String::new();
    for (input, module, generated) in files {
        let out_file = out.join(format!("{module}.rs"));
        let dependencies = slint_build::compile_with_output_path(
            manifest.join("ui").join(input),
            &out_file,
            slint_build::CompilerConfiguration::new(),
        )
        .expect("slint compilation failed");
        println!(
            "cargo:rerun-if-changed={}",
            manifest.join("ui").join(input).display()
        );
        for dep in dependencies {
            println!("cargo:rerun-if-changed={}", dep.display());
        }
        let dead_code_allow = if test_only.contains(input) {
            "#[allow(dead_code)]\n"
        } else {
            ""
        };
        wrapper.push_str(&format!(
            "{dead_code_allow}pub mod {module} {{\n    include!({out_file:?});\n    pub use {generated}::*;\n}}\n",
            out_file = out_file.display().to_string(),
        ));
    }

    let wrapper_path = out.join("modules.rs");
    fs::write(&wrapper_path, wrapper).expect("write modules.rs");
    println!(
        "cargo:rustc-env=SLINT_INCLUDE_GENERATED={}",
        wrapper_path.display()
    );

    // Build metadata for the About dialog's diagnostics text (the C++
    // configure step defines FREESCP_GIT_COMMIT the same way).
    let git_commit = std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(&manifest)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|commit| !commit.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=FREESCP_GIT_COMMIT={git_commit}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-env-changed=SLINT_STYLE");
    println!("cargo:rerun-if-env-changed=SLINT_FONT_SIZES");
    println!("cargo:rerun-if-env-changed=SLINT_SCALE_FACTOR");
    println!("cargo:rerun-if-env-changed=SLINT_ASSET_SECTION");
    println!("cargo:rerun-if-env-changed=SLINT_EMBED_RESOURCES");
    println!("cargo:rerun-if-env-changed=SLINT_EMIT_DEBUG_INFO");
    println!("cargo:rerun-if-env-changed=SLINT_LIVE_PREVIEW");
}

// Embeds the application icon (and file metadata) into the PE resource
// section, so freescp-app.exe shows the FreeSCP icon in Explorer, the
// taskbar and installers without needing an external .ico next to it.
// CARGO_CFG_WINDOWS reflects the TARGET (unlike #[cfg(windows)], which is
// evaluated against the host), so resources are also embedded when
// cross-compiling Windows binaries from Linux (windres provided by
// llvm-mingw). winresource is an ungated build-dependency; its compile()
// call below is only reached for Windows targets.
fn embed_windows_resources(manifest: &std::path::Path) {
    if env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }
    let icon = manifest.join("../../assets/program/icon-freescp.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    let mut res = winresource::WindowsResource::new();
    res.set_icon(icon.to_str().expect("icon path is valid UTF-8"));
    res.set("FileDescription", "FreeSCP");
    res.set("ProductName", "FreeSCP");
    res.compile()
        .expect("failed to compile Windows resources (app icon)");
}
