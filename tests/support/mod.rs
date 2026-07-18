use std::collections::BTreeMap;
use std::path::PathBuf;

use codex_ssh_bridge::config::{Config, HostLimitOverrides, HostProfile};

pub fn config_with_host(alias: &str, root: &str) -> Config {
    let mut hosts = BTreeMap::new();
    hosts.insert(
        alias.to_owned(),
        HostProfile {
            root: root.to_owned(),
            description: None,
            read_only: false,
            limits: HostLimitOverrides::default(),
        },
    );
    Config {
        hosts,
        ..Config::default()
    }
}

pub fn fake_ssh_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-ssh.sh")
}
