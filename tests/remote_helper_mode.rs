#![deny(unsafe_code)]

use codex_ssh_bridge::remote::{RemoteContext, ShellMetadata, ShellName};
use codex_ssh_bridge::ssh::HelperMode;

#[test]
fn helper_mode_is_serialized_with_remote_context() {
    let context = RemoteContext {
        remote: true,
        host: "dev".to_owned(),
        physical_root: "/srv/app".to_owned(),
        shell: ShellMetadata {
            kind: ShellName::Bash,
            version: Some("5.2".to_owned()),
            fallback: false,
        },
        helper_mode: Some(HelperMode::Persistent),
    };
    let value = serde_json::to_value(context).unwrap();
    assert_eq!(value["helper_mode"], "persistent");
}
