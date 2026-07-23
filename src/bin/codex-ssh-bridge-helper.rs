use std::io;

use codex_ssh_bridge::remote_helper::{HelperConfig, run};

fn main() {
    remove_bootstrap_artifact();
    if let Err(error) = run(io::stdin(), io::stdout(), parse_config()) {
        eprintln!("codex-ssh-bridge-helper: {error}");
        std::process::exit(74);
    }
}

fn remove_bootstrap_artifact() {
    let Some(path) = std::env::var_os("CODEX_SSH_HELPER_PATH") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let parent = path.parent().map(std::path::Path::to_owned);
    let _ = std::fs::remove_file(&path);
    if let Some(parent) = parent {
        let _ = std::fs::remove_dir(parent);
    }
}

fn parse_config() -> HelperConfig {
    let mut args = std::env::args_os().skip(1);
    let mut max_frame_bytes = codex_ssh_bridge::MAX_FRAME_BYTES;
    while let Some(argument) = args.next() {
        if argument == "--max-frame" {
            let Some(value) = args.next() else {
                eprintln!("codex-ssh-bridge-helper: --max-frame requires a positive integer");
                std::process::exit(64);
            };
            max_frame_bytes = value.to_string_lossy().parse().unwrap_or(0);
        } else {
            eprintln!("codex-ssh-bridge-helper: unknown argument");
            std::process::exit(64);
        }
    }
    HelperConfig::new(max_frame_bytes)
}
