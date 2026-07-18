#![allow(
    clippy::result_large_err,
    reason = "Task 1 fixes BridgeResult<T> to an inline BridgeError representation"
)]

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;

use super::{RuntimePaths, SshPolicy, build_ssh_argv};
use crate::capability::{
    CAPABILITY_PROBE_SCRIPT, Capability, CapabilityCache, ShellKind, ShellRequest, ShellSelection,
    parse_probe_output, select_shell,
};
use crate::config::{Config, EffectiveLimits};
use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{CaptureLimits, CapturedOutput, OutputStore, StderrSignals};
use crate::path::RemotePath;
use crate::quote::{fixed_command, shell_word};

const DEFAULT_SSH_EXECUTABLE: &str = "/usr/bin/ssh";
const RESOLVED_STDOUT_LIMIT: u64 = 1024 * 1024;
const RESOLVED_STDERR_LIMIT: u64 = 64 * 1024;
const PROBE_OUTPUT_LIMIT: u64 = 1024 * 1024;
const REMOTE_TIMEOUT_RETURN_GRACE: Duration = Duration::from_millis(200);
const TERM_GRACE: Duration = Duration::from_millis(50);
const DRAIN_GRACE: Duration = Duration::from_millis(125);

const SSH_G_OPTIONS: &[&str] = &[
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "RequestTTY=no",
    "ControlPersist=300",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    pub host: String,
    pub command: String,
    pub shell: ShellRequest,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub status: i32,
    pub elapsed_ms: u64,
    pub shell: ShellSelection,
    pub output: CapturedOutput,
    pub remote_process_may_continue: bool,
}

pub struct SshRunner {
    config: Arc<Config>,
    runtime: RuntimePaths,
    output_store: Arc<OutputStore>,
    executable: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    capabilities: CapabilityCache,
    identities: Mutex<HashMap<String, String>>,
    initializers: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    global_limit: Arc<Semaphore>,
    host_limits: StdMutex<HashMap<String, Arc<Semaphore>>>,
}

impl SshRunner {
    pub fn new(
        config: Arc<Config>,
        runtime: RuntimePaths,
        output_store: Arc<OutputStore>,
    ) -> BridgeResult<Self> {
        Self::with_executable(
            config,
            runtime,
            output_store,
            PathBuf::from(DEFAULT_SSH_EXECUTABLE),
            BTreeMap::new(),
        )
    }

    /// Constructs a runner with a trusted local OpenSSH-compatible executable.
    ///
    /// The caller grants the executable and fixed environment local execution
    /// authority. Neither value is read from remote-host configuration.
    pub fn with_executable(
        config: Arc<Config>,
        runtime: RuntimePaths,
        output_store: Arc<OutputStore>,
        executable: PathBuf,
        environment: BTreeMap<OsString, OsString>,
    ) -> BridgeResult<Self> {
        if !executable.is_absolute() {
            return Err(BridgeError::invalid_argument(
                "SSH executable must be an absolute path",
            ));
        }
        if config.limits.global_concurrency == 0 {
            return Err(BridgeError::invalid_config(
                "global_concurrency must be positive",
            ));
        }
        let global_concurrency = config.limits.global_concurrency;
        Ok(Self {
            config,
            runtime,
            output_store,
            executable,
            environment,
            capabilities: CapabilityCache::default(),
            identities: Mutex::new(HashMap::new()),
            initializers: Mutex::new(HashMap::new()),
            global_limit: Arc::new(Semaphore::new(global_concurrency)),
            host_limits: StdMutex::new(HashMap::new()),
        })
    }

    pub async fn execute(
        &self,
        request: RunRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<RunResult> {
        let operation_started = Instant::now();
        let host = self.config.host(&request.host)?;
        let root = host.profile.root.clone();
        let limits = host.limits;
        validate_request(&request, limits)?;

        let initializer = self.initializer(&request.host).await;
        let initialize_guard = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(cancelled_error(false, 0)),
            guard = initializer.lock() => guard,
        };
        let _reservation = self
            .acquire_operation(&request.host, limits.per_host_concurrency, &cancel)
            .await?;
        if cancel.is_cancelled() {
            return Err(cancelled_error(false, 0));
        }

        let (policy, capability) = self
            .initialize_host(&request.host, &root, limits.connect_timeout_ms, &cancel)
            .await?;
        drop(initialize_guard);
        if cancel.is_cancelled() {
            return Err(cancelled_error(false, 0));
        }
        let shell = select_shell(&capability, request.shell)?;
        let timeout_ms = u64::try_from(request.timeout.as_millis())
            .map_err(|_| BridgeError::invalid_argument("command timeout is too large"))?;
        let remote_timeout = !matches!(shell.shell, ShellKind::Login)
            && capability.tools.get("timeout") == Some(&true);
        let remote_command =
            render_remote_command(&request.command, &shell.shell, remote_timeout, timeout_ms)?;
        let argv = build_ssh_argv(&policy, &request.host, &remote_command);
        let local_deadline = if remote_timeout {
            request
                .timeout
                .checked_add(REMOTE_TIMEOUT_RETURN_GRACE)
                .ok_or_else(|| BridgeError::invalid_argument("command timeout is too large"))?
        } else {
            request.timeout
        };
        let outcome = self
            .run_child(
                ChildSpec {
                    argv,
                    stdin: request.stdin,
                    capture_limits: CaptureLimits {
                        preview_bytes: limits.preview_bytes,
                        max_output_bytes: limits.max_output_bytes,
                    },
                    deadline: local_deadline,
                    phase: Phase::Command {
                        remote_timeout_wrapped: remote_timeout,
                    },
                },
                &cancel,
                &request.host,
            )
            .await?;

        Ok(RunResult {
            status: 0,
            elapsed_ms: elapsed_ms(operation_started.elapsed()),
            shell,
            output: outcome.output,
            remote_process_may_continue: false,
        })
    }

    async fn initializer(&self, host: &str) -> Arc<Mutex<()>> {
        let mut initializers = self.initializers.lock().await;
        Arc::clone(
            initializers
                .entry(host.to_owned())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    async fn initialize_host(
        &self,
        host: &str,
        root: &str,
        connect_timeout_ms: u64,
        cancel: &CancellationToken,
    ) -> BridgeResult<(SshPolicy, Arc<Capability>)> {
        let cached_identity = self.identities.lock().await.get(host).cloned();
        let identity = match cached_identity {
            Some(identity) => identity,
            None => {
                let identity = self
                    .resolve_identity_once(host, connect_timeout_ms, cancel)
                    .await?;
                self.identities
                    .lock()
                    .await
                    .insert(host.to_owned(), identity.clone());
                identity
            }
        };
        let policy = SshPolicy::for_host(
            &self.config,
            self.config.host(host)?,
            &self.runtime,
            &identity,
        )?;
        let capability = self
            .capabilities
            .get_or_probe(host, || async {
                self.probe_capability(&policy, host, root, connect_timeout_ms, cancel)
                    .await
            })
            .await?;
        Ok((policy, capability))
    }

    async fn resolve_identity_once(
        &self,
        host: &str,
        connect_timeout_ms: u64,
        cancel: &CancellationToken,
    ) -> BridgeResult<String> {
        let mut argv = vec![OsString::from("-G")];
        for option in SSH_G_OPTIONS {
            argv.push(OsString::from("-o"));
            argv.push(OsString::from(option));
        }
        argv.push(OsString::from("--"));
        argv.push(OsString::from(host));
        let total_limit = RESOLVED_STDOUT_LIMIT + RESOLVED_STDERR_LIMIT;
        let outcome = self
            .run_child(
                ChildSpec {
                    argv,
                    stdin: None,
                    capture_limits: CaptureLimits {
                        preview_bytes: usize::try_from(total_limit * 2)
                            .expect("resolved output bound fits usize"),
                        max_output_bytes: total_limit,
                    },
                    deadline: Duration::from_millis(connect_timeout_ms),
                    phase: Phase::Resolve,
                },
                cancel,
                host,
            )
            .await
            .map_err(|error| {
                if error.code == ErrorCode::OutputLimit {
                    BridgeError::new(
                        ErrorCode::ProtocolError,
                        "resolved SSH configuration exceeded its output limit",
                        false,
                    )
                } else {
                    error
                }
            })?;
        if outcome.output.stdout.bytes_seen > RESOLVED_STDOUT_LIMIT
            || outcome.output.stderr.bytes_seen > RESOLVED_STDERR_LIMIT
        {
            self.output_store.discard(&outcome.output).await;
            return Err(BridgeError::new(
                ErrorCode::ProtocolError,
                "resolved SSH configuration exceeded its stream limit",
                false,
            ));
        }
        let stdout = joined_preview(&outcome.output.stdout);
        self.output_store.discard(&outcome.output).await;
        let digest = Sha256::digest(stdout);
        Ok(hex_digest(&digest))
    }

    async fn probe_capability(
        &self,
        policy: &SshPolicy,
        host: &str,
        root: &str,
        connect_timeout_ms: u64,
        cancel: &CancellationToken,
    ) -> BridgeResult<Capability> {
        let requested_root = RemotePath::resolve(root, ".")?;
        let remote_command = fixed_command(CAPABILITY_PROBE_SCRIPT, &[root])?;
        let outcome = self
            .run_child(
                ChildSpec {
                    argv: build_ssh_argv(policy, host, &remote_command),
                    stdin: None,
                    capture_limits: CaptureLimits {
                        preview_bytes: usize::try_from(PROBE_OUTPUT_LIMIT * 2)
                            .expect("probe output bound fits usize"),
                        max_output_bytes: PROBE_OUTPUT_LIMIT,
                    },
                    deadline: Duration::from_millis(connect_timeout_ms),
                    phase: Phase::Probe,
                },
                cancel,
                host,
            )
            .await?;
        let stdout = joined_preview(&outcome.output.stdout);
        let parsed = parse_probe_output(&stdout, &requested_root);
        self.output_store.discard(&outcome.output).await;
        parsed
    }

    async fn acquire_operation(
        &self,
        host: &str,
        per_host: usize,
        cancel: &CancellationToken,
    ) -> BridgeResult<OperationReservation> {
        let host_limit = {
            let mut limits = self.host_limits.lock().map_err(|_| {
                BridgeError::new(ErrorCode::Io, "host limiter lock poisoned", false)
            })?;
            Arc::clone(
                limits
                    .entry(host.to_owned())
                    .or_insert_with(|| Arc::new(Semaphore::new(per_host))),
            )
        };

        loop {
            let global = match Arc::clone(&self.global_limit).try_acquire_owned() {
                Ok(permit) => permit,
                Err(TryAcquireError::NoPermits) => {
                    wait_for_permit(Arc::clone(&self.global_limit), cancel).await?;
                    continue;
                }
                Err(TryAcquireError::Closed) => return Err(limiter_closed()),
            };
            match Arc::clone(&host_limit).try_acquire_owned() {
                Ok(host) => {
                    return Ok(OperationReservation {
                        _global: global,
                        _host: host,
                    });
                }
                Err(TryAcquireError::NoPermits) => {
                    drop(global);
                    wait_for_permit(Arc::clone(&host_limit), cancel).await?;
                }
                Err(TryAcquireError::Closed) => return Err(limiter_closed()),
            }
        }
    }

    async fn run_child(
        &self,
        spec: ChildSpec,
        cancel: &CancellationToken,
        host: &str,
    ) -> BridgeResult<ChildOutcome> {
        if cancel.is_cancelled() {
            return Err(cancelled_error(false, 0));
        }
        let started = Instant::now();
        let mut command = Command::new(&self.executable);
        command
            .args(spec.argv)
            .envs(&self.environment)
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // SAFETY: pre_exec runs in the child after fork and calls only setpgid,
        // an async-signal-safe libc function. It captures no parent references.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let mut child = command.spawn().map_err(BridgeError::io)?;
        let process_group = child
            .id()
            .ok_or_else(|| BridgeError::new(ErrorCode::Io, "SSH child has no process id", false))?
            as i32;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BridgeError::new(ErrorCode::Io, "SSH stdout pipe is missing", false))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BridgeError::new(ErrorCode::Io, "SSH stderr pipe is missing", false))?;
        let child_stdin = child.stdin.take();
        let stdin_task = tokio::spawn(write_stdin(child_stdin, spec.stdin));
        let output_limit = CancellationToken::new();
        let capture_task = {
            let store = Arc::clone(&self.output_store);
            let output_limit = output_limit.clone();
            tokio::spawn(async move {
                store
                    .capture(stdout, stderr, spec.capture_limits, output_limit)
                    .await
            })
        };

        let mut wait = Box::pin(child.wait());
        let stop = tokio::select! {
            biased;
            result = &mut wait => Stop::Exited(result.map_err(BridgeError::io)?),
            () = cancel.cancelled() => Stop::Cancelled,
            () = output_limit.cancelled() => Stop::OutputLimit,
            () = tokio::time::sleep(spec.deadline) => Stop::Deadline,
        };
        drop(wait);

        match stop {
            Stop::Exited(status) => {
                let output = match finish_capture(capture_task).await {
                    Ok(output) => output,
                    Err(mut error) if error.code == ErrorCode::OutputLimit => {
                        error.details.host = Some(host.to_owned());
                        error.details.elapsed_ms = Some(elapsed_ms(started.elapsed()));
                        error.details.remote_process_may_continue =
                            Some(spec.phase.remote_started());
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                };
                finish_stdin(stdin_task).await?;
                self.classify_exit(status, output, spec.phase, host, started.elapsed())
                    .await
            }
            Stop::Cancelled | Stop::OutputLimit | Stop::Deadline => {
                terminate_process_group(process_group, &mut child).await;
                let _ = finish_stdin(stdin_task).await;
                let capture = finish_capture_bounded(capture_task).await;
                let bytes_seen = capture
                    .as_ref()
                    .ok()
                    .map(|output| output.aggregate_bytes)
                    .or_else(|| {
                        capture
                            .as_ref()
                            .err()
                            .and_then(|error| error.details.bytes_seen)
                    })
                    .unwrap_or(0);
                if let Ok(output) = &capture {
                    self.output_store.discard(output).await;
                }
                let mut error = match stop {
                    Stop::Cancelled => cancelled_error(spec.phase.remote_started(), bytes_seen),
                    Stop::Deadline => spec.phase.timeout_error(bytes_seen),
                    Stop::OutputLimit => match capture {
                        Err(error) if error.code == ErrorCode::OutputLimit => error,
                        _ => BridgeError::new(
                            ErrorCode::OutputLimit,
                            "command output exceeded the configured limit",
                            false,
                        ),
                    },
                    Stop::Exited(_) => unreachable!(),
                };
                error.details.host = Some(host.to_owned());
                error.details.elapsed_ms = Some(elapsed_ms(started.elapsed()));
                if matches!(stop, Stop::OutputLimit) {
                    error.details.bytes_seen = Some(bytes_seen);
                    error.details.remote_process_may_continue = Some(spec.phase.remote_started());
                }
                Err(error)
            }
        }
    }

    async fn classify_exit(
        &self,
        status: ExitStatus,
        output: CapturedOutput,
        phase: Phase,
        host: &str,
        elapsed: Duration,
    ) -> BridgeResult<ChildOutcome> {
        let code = status.code().unwrap_or(-1);
        if code == 0 {
            return Ok(ChildOutcome { output });
        }
        let error_code = if phase.remote_timeout_wrapped() && code == 124 {
            ErrorCode::CommandTimeout
        } else if code == 255 {
            classify_ssh_255(output.stderr_signals)
        } else {
            ErrorCode::RemoteExit
        };
        let retryable = error_code == ErrorCode::ConnectTimeout;
        let message = match error_code {
            ErrorCode::HostKeyUnknown => "SSH host key is unknown or changed",
            ErrorCode::AuthRequired => "SSH authentication is required",
            ErrorCode::ConnectTimeout => "SSH connection timed out",
            ErrorCode::CommandTimeout => "remote command timed out",
            ErrorCode::RemoteExit => "remote command exited unsuccessfully",
            _ => "SSH operation failed",
        };
        let mut error = BridgeError::new(error_code, message, retryable);
        error.details.host = Some(host.to_owned());
        error.details.elapsed_ms = Some(elapsed_ms(elapsed));
        error.details.exit_status = Some(code);
        error.details.bytes_seen = Some(output.aggregate_bytes);
        if error_code == ErrorCode::CommandTimeout {
            error.details.remote_process_may_continue = Some(true);
        }
        self.output_store.discard(&output).await;
        Err(error)
    }
}

struct OperationReservation {
    _global: OwnedSemaphorePermit,
    _host: OwnedSemaphorePermit,
}

struct ChildOutcome {
    output: CapturedOutput,
}

struct ChildSpec {
    argv: Vec<OsString>,
    stdin: Option<Vec<u8>>,
    capture_limits: CaptureLimits,
    deadline: Duration,
    phase: Phase,
}

#[derive(Clone, Copy)]
enum Phase {
    Resolve,
    Probe,
    Command { remote_timeout_wrapped: bool },
}

impl Phase {
    fn remote_started(self) -> bool {
        !matches!(self, Self::Resolve)
    }

    fn remote_timeout_wrapped(self) -> bool {
        matches!(
            self,
            Self::Command {
                remote_timeout_wrapped: true
            }
        )
    }

    fn timeout_error(self, bytes_seen: u64) -> BridgeError {
        let (code, message, retryable) = match self {
            Self::Resolve => (
                ErrorCode::ConnectTimeout,
                "SSH configuration timed out",
                true,
            ),
            Self::Probe => (
                ErrorCode::ConnectTimeout,
                "SSH capability probe timed out",
                true,
            ),
            Self::Command { .. } => (ErrorCode::CommandTimeout, "remote command timed out", false),
        };
        let mut error = BridgeError::new(code, message, retryable);
        error.details.remote_process_may_continue = Some(self.remote_started());
        error.details.bytes_seen = Some(bytes_seen);
        error
    }
}

enum Stop {
    Exited(ExitStatus),
    Cancelled,
    OutputLimit,
    Deadline,
}

async fn wait_for_permit(
    semaphore: Arc<Semaphore>,
    cancel: &CancellationToken,
) -> BridgeResult<()> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(cancelled_error(false, 0)),
        result = semaphore.acquire_owned() => {
            drop(result.map_err(|_| limiter_closed())?);
            Ok(())
        }
    }
}

fn limiter_closed() -> BridgeError {
    BridgeError::new(ErrorCode::Io, "SSH concurrency limiter is closed", false)
}

fn validate_request(request: &RunRequest, limits: EffectiveLimits) -> BridgeResult<()> {
    let timeout_ms = request.timeout.as_millis();
    if timeout_ms == 0 || timeout_ms > u128::from(limits.command_timeout_ms) {
        return Err(BridgeError::invalid_argument(format!(
            "command timeout must be between 1 and {} milliseconds",
            limits.command_timeout_ms
        )));
    }
    if request.command.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "NUL is not representable in a remote command",
        ));
    }
    if request
        .stdin
        .as_ref()
        .is_some_and(|stdin| stdin.len() > limits.max_write_bytes)
    {
        return Err(BridgeError::new(
            ErrorCode::RequestTooLarge,
            "command input exceeds the configured limit",
            false,
        ));
    }
    Ok(())
}

fn render_remote_command(
    command: &str,
    shell: &ShellKind,
    remote_timeout: bool,
    timeout_ms: u64,
) -> BridgeResult<String> {
    if matches!(shell, ShellKind::Login) {
        return Ok(command.to_owned());
    }
    let quoted = shell_word(command)?;
    let timeout_prefix = if remote_timeout {
        format!("timeout --signal=TERM --kill-after=1s {timeout_ms}ms ")
    } else {
        String::new()
    };
    match shell {
        ShellKind::Bash { .. } => Ok(format!(
            "exec {timeout_prefix}bash --noprofile --norc -c {quoted}"
        )),
        ShellKind::PosixSh => Ok(format!("exec {timeout_prefix}sh -c {quoted}")),
        ShellKind::Login => unreachable!(),
    }
}

async fn write_stdin(
    mut stdin: Option<tokio::process::ChildStdin>,
    bytes: Option<Vec<u8>>,
) -> std::io::Result<()> {
    if let Some(mut stdin) = stdin.take() {
        if let Some(bytes) = bytes
            && let Err(error) = stdin.write_all(&bytes).await
            && error.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(error);
        }
        stdin.shutdown().await?;
    }
    Ok(())
}

async fn finish_stdin(task: JoinHandle<std::io::Result<()>>) -> BridgeResult<()> {
    task.await
        .map_err(|error| BridgeError::new(ErrorCode::Io, error.to_string(), false))?
        .map_err(BridgeError::io)
}

async fn finish_capture(
    task: JoinHandle<BridgeResult<CapturedOutput>>,
) -> BridgeResult<CapturedOutput> {
    task.await
        .map_err(|error| BridgeError::new(ErrorCode::Io, error.to_string(), false))?
}

async fn finish_capture_bounded(
    mut task: JoinHandle<BridgeResult<CapturedOutput>>,
) -> BridgeResult<CapturedOutput> {
    match timeout(DRAIN_GRACE, &mut task).await {
        Ok(result) => {
            result.map_err(|error| BridgeError::new(ErrorCode::Io, error.to_string(), false))?
        }
        Err(_) => {
            task.abort();
            Err(BridgeError::new(
                ErrorCode::Io,
                "SSH output drain did not stop after termination",
                false,
            ))
        }
    }
}

async fn terminate_process_group(process_group: i32, child: &mut Child) {
    signal_process_group(process_group, libc::SIGTERM);
    tokio::time::sleep(TERM_GRACE).await;
    signal_process_group(process_group, libc::SIGKILL);
    let _ = child.wait().await;
}

fn signal_process_group(process_group: i32, signal: i32) {
    // SAFETY: kill accepts any integer process-group id. The negative id
    // targets only the child-created process group and retains no pointer.
    let result = unsafe { libc::kill(-process_group, signal) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            // Termination remains best effort; the child is reaped afterward.
        }
    }
}

fn classify_ssh_255(signals: StderrSignals) -> ErrorCode {
    if signals.host_key {
        ErrorCode::HostKeyUnknown
    } else if signals.authentication {
        ErrorCode::AuthRequired
    } else if signals.connect_timeout {
        ErrorCode::ConnectTimeout
    } else {
        ErrorCode::RemoteExit
    }
}

fn cancelled_error(remote_started: bool, bytes_seen: u64) -> BridgeError {
    let mut error = BridgeError::new(ErrorCode::Cancelled, "SSH operation was cancelled", false);
    error.details.remote_process_may_continue = Some(remote_started);
    error.details.bytes_seen = Some(bytes_seen);
    error
}

fn joined_preview(preview: &crate::output::OutputPreview) -> Vec<u8> {
    let mut bytes = preview.head.clone();
    bytes.extend_from_slice(&preview.tail);
    bytes
}

fn hex_digest(digest: &[u8]) -> String {
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn elapsed_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
