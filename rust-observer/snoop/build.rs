use std::{path::Path, process::Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=SNOOP_SKIP_EBPF_BUILD");
    println!("cargo:rerun-if-env-changed=SNOOP_EBPF_OBJ");
    println!("cargo:rerun-if-changed=../snoop-ebpf");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return Ok(());
    }

    let out_dir = std::env::var("OUT_DIR")?;
    let out_file = Path::new(&out_dir).join("snoop-ebpf");

    if std::env::var("SNOOP_SKIP_EBPF_BUILD").is_ok() {
        std::fs::write(&out_file, b"")?;
        return Ok(());
    }

    if let Ok(obj_path) = std::env::var("SNOOP_EBPF_OBJ") {
        let obj_path = Path::new(&obj_path)
            .canonicalize()
            .map_err(|err| format!("SNOOP_EBPF_OBJ={obj_path}: {err}"))?;
        println!("cargo:rerun-if-changed={}", obj_path.display());
        std::fs::copy(&obj_path, &out_file)?;
        return Ok(());
    }

    let ebpf_target_dir = Path::new(&out_dir).join("ebpf-target");
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("CARGO_MANIFEST_DIR has no parent")?;

    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--release",
            "--package",
            "snoop-ebpf",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .env("CARGO_TARGET_DIR", &ebpf_target_dir)
        .env_remove("RUSTFLAGS")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env("RUSTUP_TOOLCHAIN", "nightly")
        .current_dir(workspace_root)
        .status()?;

    if !status.success() {
        return Err("rustup run nightly cargo build (snoop-ebpf) failed".into());
    }

    let compiled = ebpf_target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("snoop-ebpf");
    std::fs::copy(&compiled, &out_file)?;
    Ok(())
}
