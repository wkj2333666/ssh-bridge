use std::ffi::{OsStr, OsString};

use super::SshPolicy;

pub fn build_ssh_argv(policy: &SshPolicy, host: &str, remote_command: &str) -> Vec<OsString> {
    let mut argv = policy.options.clone();
    argv.push(OsString::from("--"));
    argv.push(OsString::from(host));
    if !remote_command.is_empty() {
        argv.push(OsString::from(remote_command));
    }
    debug_assert!(argv.iter().any(|argument| argument == OsStr::new("--")));
    argv
}
