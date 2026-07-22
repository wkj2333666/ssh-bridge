#![deny(unsafe_code)]

mod support;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use codex_ssh_bridge::capability::ShellRequest;
use codex_ssh_bridge::output::OutputStore;
use codex_ssh_bridge::ssh::{RunRequest, RuntimePaths, SshRunner};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use support::config_with_host;

fn session_runner(base: &TempDir, log: &std::path::Path) -> Arc<SshRunner> {
    let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
    let store = Arc::new(OutputStore::new(&runtime).unwrap());
    let environment = BTreeMap::from([
        (
            OsString::from("FAKE_SSH_MODE"),
            OsString::from("local-fixed"),
        ),
        (OsString::from("FAKE_SSH_ROOT"), OsString::from("/tmp")),
        (OsString::from("FAKE_SSH_SHELL"), OsString::from("sh")),
        (OsString::from("FAKE_SSH_LOG"), log.as_os_str().to_owned()),
    ]);
    Arc::new(
        SshRunner::with_executable(
            Arc::new(config_with_host("dev", "/tmp")),
            runtime,
            store,
            support::fake_ssh_path(),
            environment,
        )
        .unwrap(),
    )
}

fn request(command: &str) -> RunRequest {
    RunRequest {
        host: "dev".to_owned(),
        command: command.to_owned(),
        cwd: "/tmp".to_owned(),
        shell: ShellRequest::Sh,
        stdin: None,
        timeout: Duration::from_secs(5),
    }
}

#[tokio::test]
async fn one_host_reuses_one_persistent_ssh_dispatcher() {
    let base = TempDir::new().unwrap();
    let log = base.path().join("ssh.log");
    let runner = session_runner(&base, &log);
    let first = runner
        .execute(request("printf first"), CancellationToken::new())
        .await
        .unwrap();
    let second = runner
        .execute(request("printf second"), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(first.status, 0);
    assert_eq!(second.status, 0);
    assert_eq!(String::from_utf8_lossy(&first.output.stdout.head), "first");
    assert_eq!(
        String::from_utf8_lossy(&second.output.stdout.head),
        "second"
    );
    let log = fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().filter(|line| *line == "S").count(), 1, "{log}");
}

#[tokio::test]
async fn independent_session_requests_complete_concurrently() {
    let base = TempDir::new().unwrap();
    let log = base.path().join("ssh.log");
    let runner = session_runner(&base, &log);
    let slow = {
        let runner = Arc::clone(&runner);
        tokio::spawn(async move {
            runner
                .execute(request("sleep 0.2; printf slow"), CancellationToken::new())
                .await
                .unwrap()
        })
    };
    let fast = {
        let runner = Arc::clone(&runner);
        tokio::spawn(async move {
            runner
                .execute(request("printf fast"), CancellationToken::new())
                .await
                .unwrap()
        })
    };
    let fast = fast.await.unwrap();
    let slow = slow.await.unwrap();
    assert_eq!(String::from_utf8_lossy(&fast.output.stdout.head), "fast");
    assert_eq!(String::from_utf8_lossy(&slow.output.stdout.head), "slow");
}

#[tokio::test]
async fn session_preserves_large_binary_stdin_across_pipe_short_reads() {
    let base = TempDir::new().unwrap();
    let log = base.path().join("ssh.log");
    let runner = session_runner(&base, &log);
    let stdin = vec![0xA5; 512 * 1024 + 123];
    let mut request = request("wc -c");
    request.stdin = Some(stdin.clone());
    let result = runner
        .execute(request, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(result.status, 0);
    assert_eq!(
        String::from_utf8_lossy(&result.output.stdout.head),
        format!("{}\n", stdin.len())
    );
}
