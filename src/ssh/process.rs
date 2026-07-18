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
use tokio::process::Command;
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
use crate::output::{
    CaptureLimits, CapturedOutput, InternalCapturedOutput, InternalSpoolRegistration, OutputPage,
    OutputProvenance, OutputReference, OutputStore, StderrSignals, StreamKind,
};
use crate::path::RemotePath;
use crate::quote::shell_word;

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

#[derive(Clone)]
pub(crate) struct FixedRunRequest {
    pub host: String,
    pub script: &'static str,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub required_capabilities: &'static [&'static str],
    pub stdout_limit: u64,
    pub stderr_limit: u64,
    pub timeout: Duration,
    pub cleanup: InternalSpoolRegistration,
}

pub(crate) struct FixedRunResult {
    pub capability: Arc<Capability>,
    pub shell: ShellSelection,
    pub output: InternalCapturedOutput,
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
                    internal_registration: None,
                },
                &cancel,
                &request.host,
            )
            .await?;

        let output = outcome.output.into_public()?;
        self.output_store
            .set_provenance(
                &output,
                OutputProvenance {
                    host: request.host.clone(),
                    physical_root: capability.physical_root.clone(),
                    shell: shell.clone(),
                },
            )
            .await;
        Ok(RunResult {
            status: 0,
            elapsed_ms: elapsed_ms(operation_started.elapsed()),
            shell,
            output,
            remote_process_may_continue: false,
        })
    }

    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    pub(crate) async fn cached_capability(&self, host: &str) -> Option<Arc<Capability>> {
        self.capabilities.get(host).await
    }

    pub(crate) async fn invalidate_capability(&self, host: &str) -> bool {
        self.capabilities.invalidate(host).await
    }

    pub(crate) async fn read_output(
        &self,
        reference: &OutputReference,
        stream: StreamKind,
        offset: u64,
        max_bytes: usize,
    ) -> BridgeResult<OutputPage> {
        self.output_store
            .read(reference, stream, offset, max_bytes)
            .await
    }

    pub(crate) async fn output_provenance(
        &self,
        reference: &OutputReference,
    ) -> BridgeResult<OutputProvenance> {
        self.output_store.provenance(reference).await
    }

    pub(crate) async fn execute_fixed(
        &self,
        request: FixedRunRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<FixedRunResult> {
        let first = self
            .execute_fixed_once(request.clone(), cancel.clone())
            .await?;
        match fixed_capability_mismatch(&first.output, request.required_capabilities).await? {
            None => Ok(first),
            Some(_) => {
                self.invalidate_capability(&request.host).await;
                let second = self.execute_fixed_once(request.clone(), cancel).await?;
                match fixed_capability_mismatch(&second.output, request.required_capabilities)
                    .await?
                {
                    None => Ok(second),
                    Some(_) => Err(BridgeError::new(
                        ErrorCode::RemoteCapabilityMissing,
                        "remote read capability remained unavailable after reprobe",
                        false,
                    )),
                }
            }
        }
    }

    async fn execute_fixed_once(
        &self,
        request: FixedRunRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<FixedRunResult> {
        let host = self.config.host(&request.host)?;
        let limits = host.limits;
        let root = host.profile.root.clone();
        if request.timeout.is_zero()
            || request.timeout > Duration::from_millis(limits.command_timeout_ms)
        {
            return Err(BridgeError::invalid_argument(
                "fixed command timeout is outside the configured limit",
            ));
        }
        let remote_command = render_fixed_command(request.script, &request.args)?;
        let transport_bytes = remote_command
            .len()
            .checked_add(request.stdin.as_ref().map_or(0, Vec::len))
            .ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::RequestTooLarge,
                    "fixed request exceeds the configured frame limit",
                    false,
                )
            })?;
        if transport_bytes > limits.max_frame_bytes
            || request.stdout_limit == 0
            || request.stderr_limit == 0
        {
            return Err(BridgeError::new(
                ErrorCode::RequestTooLarge,
                "fixed request exceeds the configured frame limit",
                false,
            ));
        }
        let capture_limit = request
            .stdout_limit
            .checked_add(request.stderr_limit)
            .ok_or_else(|| {
                BridgeError::new(
                    ErrorCode::RequestTooLarge,
                    "fixed output limit overflowed",
                    false,
                )
            })?;
        if capture_limit > limits.max_output_bytes {
            return Err(BridgeError::new(
                ErrorCode::RequestTooLarge,
                "fixed output exceeds the configured limit",
                false,
            ));
        }

        let initializer = self.initializer(&request.host).await;
        let initialize_guard = tokio::select! { biased; () = cancel.cancelled() => return Err(cancelled_error(false, 0)), guard = initializer.lock() => guard };
        let _reservation = self
            .acquire_operation(&request.host, limits.per_host_concurrency, &cancel)
            .await?;
        let (policy, capability) = self
            .initialize_host(&request.host, &root, limits.connect_timeout_ms, &cancel)
            .await?;
        drop(initialize_guard);
        for key in request.required_capabilities {
            if capability.tools.get(*key) != Some(&true) {
                return Err(BridgeError::new(
                    ErrorCode::RemoteCapabilityMissing,
                    "remote host lacks a required read capability",
                    false,
                ));
            }
        }
        let shell = ShellSelection {
            shell: ShellKind::PosixSh,
            fallback: false,
        };
        let outcome = self
            .run_child(
                ChildSpec {
                    argv: build_ssh_argv(&policy, &request.host, &remote_command),
                    stdin: request.stdin,
                    capture_limits: CaptureLimits {
                        preview_bytes: 1,
                        max_output_bytes: capture_limit,
                    },
                    deadline: request.timeout,
                    phase: Phase::Command {
                        remote_timeout_wrapped: false,
                    },
                    internal_registration: Some(request.cleanup),
                },
                &cancel,
                &request.host,
            )
            .await?;
        let output = outcome.output.into_internal()?;
        if output.stdout_len > request.stdout_limit || output.stderr_len > request.stderr_limit {
            return Err(BridgeError::new(
                ErrorCode::OutputLimit,
                "fixed output exceeded its stream limit",
                false,
            ));
        }
        Ok(FixedRunResult {
            capability,
            shell,
            output,
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
                    internal_registration: None,
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
        let output = outcome.output.into_public()?;
        if output.stdout.bytes_seen > RESOLVED_STDOUT_LIMIT
            || output.stderr.bytes_seen > RESOLVED_STDERR_LIMIT
        {
            self.output_store.discard(&output).await;
            return Err(BridgeError::new(
                ErrorCode::ProtocolError,
                "resolved SSH configuration exceeded its stream limit",
                false,
            ));
        }
        let stdout = joined_preview(&output.stdout);
        self.output_store.discard(&output).await;
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
        let remote_command = capability_probe_command(root)?;
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
                    internal_registration: None,
                },
                cancel,
                host,
            )
            .await?;
        let output = outcome.output.into_public()?;
        let stdout = joined_preview(&output.stdout);
        let parsed = parse_probe_output(&stdout, &requested_root);
        self.output_store.discard(&output).await;
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
        let mut stdin_task = tokio::spawn(write_stdin(child_stdin, spec.stdin));
        let output_limit = CancellationToken::new();
        let mut capture_task = {
            let store = Arc::clone(&self.output_store);
            let output_limit_signal = output_limit.clone();
            let capture_cancel = cancel.clone();
            tokio::spawn(async move {
                match spec.internal_registration.clone() {
                    Some(registration) => store
                        .capture_internal(
                            stdout,
                            stderr,
                            spec.capture_limits,
                            capture_cancel,
                            output_limit_signal,
                            registration,
                        )
                        .await
                        .map(ChildCaptured::Internal),
                    None => store
                        .capture_with_limit_signal(
                            stdout,
                            stderr,
                            spec.capture_limits,
                            capture_cancel,
                            output_limit_signal,
                        )
                        .await
                        .map(ChildCaptured::Public),
                }
            })
        };
        let mut wait_task = tokio::spawn(async move { child.wait().await });
        let mut status = None;
        let mut capture = None;
        let mut stdin_finished = false;
        let deadline = tokio::time::sleep(spec.deadline);
        tokio::pin!(deadline);

        let stop = loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break Stop::Cancelled,
                () = output_limit.cancelled() => break Stop::OutputLimit,
                () = &mut deadline => break Stop::Deadline,
                result = &mut wait_task, if status.is_none() => {
                    match joined_wait(result) {
                        Ok(exit_status) => status = Some(exit_status),
                        Err(error) => break Stop::InternalError(error),
                    }
                    if capture.is_some() && stdin_finished {
                        break Stop::Completed;
                    }
                }
                result = &mut capture_task, if capture.is_none() => {
                    let result = joined_capture(result);
                    let stop_for_error = match &result {
                        Err(error) if error.code == ErrorCode::OutputLimit => {
                            Some(Stop::OutputLimit)
                        }
                        Err(error) => Some(Stop::InternalError(error.clone())),
                        Ok(_) => None,
                    };
                    capture = Some(result);
                    if let Some(stop) = stop_for_error {
                        break stop;
                    }
                    if status.is_some() && stdin_finished {
                        break Stop::Completed;
                    }
                }
                result = &mut stdin_task, if !stdin_finished => {
                    stdin_finished = true;
                    if let Err(error) = joined_stdin(result) {
                        break Stop::InternalError(error);
                    }
                    if status.is_some() && capture.is_some() {
                        break Stop::Completed;
                    }
                }
            }
        };

        match stop {
            Stop::Completed => {
                let status = status.expect("completed child status");
                let output = capture.expect("completed capture")?;
                self.classify_exit(status, output, spec.phase, host, started.elapsed())
                    .await
            }
            Stop::Cancelled | Stop::OutputLimit | Stop::Deadline | Stop::InternalError(_) => {
                terminate_process_group(process_group).await;
                if status.is_none() {
                    let _ = finish_wait(wait_task).await;
                }
                // stdin and capture share one drain-grace window so forced
                // return remains inside the 250 ms acceptance budget.
                let stdin_finish = async move {
                    if !stdin_finished {
                        let _ = finish_stdin_bounded(stdin_task).await;
                    }
                };
                let capture_finish = async move {
                    match capture {
                        Some(capture) => capture,
                        None => finish_capture_bounded(capture_task).await,
                    }
                };
                let (_, capture) = tokio::join!(stdin_finish, capture_finish);
                let bytes_seen = capture
                    .as_ref()
                    .ok()
                    .map(ChildCaptured::aggregate_bytes)
                    .or_else(|| {
                        capture
                            .as_ref()
                            .err()
                            .and_then(|error| error.details.bytes_seen)
                    })
                    .unwrap_or(0);
                if let Ok(ChildCaptured::Public(output)) = &capture {
                    self.output_store.discard(output).await;
                }
                let stopped_for_output_limit = matches!(&stop, Stop::OutputLimit);
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
                    Stop::InternalError(error) => error,
                    Stop::Completed => unreachable!(),
                };
                error.details.host = Some(host.to_owned());
                error.details.elapsed_ms = Some(elapsed_ms(started.elapsed()));
                if stopped_for_output_limit {
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
        output: ChildCaptured,
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
        } else if code == 255 && phase.allows_transport_classification() {
            classify_ssh_255(output.stderr_signals())
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
        error.details.bytes_seen = Some(output.aggregate_bytes());
        if error_code == ErrorCode::CommandTimeout
            || (code == 255 && matches!(phase, Phase::Command { .. }))
        {
            error.details.remote_process_may_continue = Some(true);
        }
        if let ChildCaptured::Public(output) = &output {
            self.output_store.discard(output).await;
        }
        Err(error)
    }
}

struct OperationReservation {
    _global: OwnedSemaphorePermit,
    _host: OwnedSemaphorePermit,
}

struct ChildOutcome {
    output: ChildCaptured,
}

enum ChildCaptured {
    Public(CapturedOutput),
    Internal(InternalCapturedOutput),
}

impl ChildCaptured {
    fn aggregate_bytes(&self) -> u64 {
        match self {
            Self::Public(output) => output.aggregate_bytes,
            Self::Internal(output) => output.aggregate_bytes,
        }
    }
    fn stderr_signals(&self) -> StderrSignals {
        match self {
            Self::Public(output) => output.stderr_signals,
            Self::Internal(_) => StderrSignals::default(),
        }
    }
    fn into_public(self) -> BridgeResult<CapturedOutput> {
        match self {
            Self::Public(output) => Ok(output),
            Self::Internal(_) => Err(BridgeError::new(
                ErrorCode::Io,
                "internal capture used by public command",
                false,
            )),
        }
    }
    fn into_internal(self) -> BridgeResult<InternalCapturedOutput> {
        match self {
            Self::Internal(output) => Ok(output),
            Self::Public(_) => Err(BridgeError::new(
                ErrorCode::Io,
                "public capture used by fixed command",
                false,
            )),
        }
    }
}

struct ChildSpec {
    argv: Vec<OsString>,
    stdin: Option<Vec<u8>>,
    capture_limits: CaptureLimits,
    deadline: Duration,
    phase: Phase,
    internal_registration: Option<InternalSpoolRegistration>,
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

    fn allows_transport_classification(self) -> bool {
        matches!(self, Self::Resolve | Self::Probe)
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
    Completed,
    Cancelled,
    OutputLimit,
    Deadline,
    InternalError(BridgeError),
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
        let duration = format_timeout_duration(timeout_ms)?;
        format!("timeout --signal=TERM --kill-after=1s {duration} ")
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

fn render_fixed_command(script: &'static str, args: &[String]) -> BridgeResult<String> {
    let mut command = format!("exec sh -c {} codex-ssh-bridge-op", shell_word(script)?);
    for argument in args {
        command.push(' ');
        command.push_str(&shell_word(argument)?);
    }
    Ok(command)
}

async fn fixed_capability_mismatch(
    output: &InternalCapturedOutput,
    required: &'static [&'static str],
) -> BridgeResult<Option<String>> {
    if output.stderr_len == 0 {
        return Ok(None);
    }
    if output.stderr_len > 4096 {
        return Ok(None);
    }
    let page = output.read(StreamKind::Stderr, 0, 4096).await?;
    const PREFIX: &[u8] = b"CODE=CAPABILITY_MISMATCH\0";
    if !page.bytes.starts_with(PREFIX) {
        return Ok(None);
    }
    if output.stdout_len != 0 || !page.eof {
        return Err(BridgeError::new(
            ErrorCode::ProtocolError,
            "capability mismatch record is malformed",
            false,
        ));
    }
    let rest = &page.bytes[PREFIX.len()..];
    let Some(value) = rest
        .strip_prefix(b"CAPABILITY=")
        .and_then(|value| value.strip_suffix(&[0]))
    else {
        return Err(BridgeError::new(
            ErrorCode::ProtocolError,
            "capability mismatch record is malformed",
            false,
        ));
    };
    if value.is_empty() || value.contains(&0) {
        return Err(BridgeError::new(
            ErrorCode::ProtocolError,
            "capability mismatch record is malformed",
            false,
        ));
    }
    let key = std::str::from_utf8(value).map_err(|_| {
        BridgeError::new(
            ErrorCode::ProtocolError,
            "capability mismatch key is invalid",
            false,
        )
    })?;
    if !required.contains(&key) {
        return Err(BridgeError::new(
            ErrorCode::ProtocolError,
            "capability mismatch named an unexpected key",
            false,
        ));
    }
    Ok(Some(key.to_owned()))
}

fn format_timeout_duration(timeout_ms: u64) -> BridgeResult<String> {
    if timeout_ms == 0 {
        return Err(BridgeError::invalid_argument(
            "command timeout must be positive",
        ));
    }
    let seconds = timeout_ms / 1000;
    let milliseconds = timeout_ms % 1000;
    Ok(format!("{seconds}.{milliseconds:03}s"))
}

fn capability_probe_command(root: &str) -> BridgeResult<String> {
    Ok(format!(
        "exec sh -c {} codex-ssh-probe {}",
        shell_word(CAPABILITY_PROBE_SCRIPT)?,
        shell_word(root)?
    ))
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

fn joined_stdin(result: Result<std::io::Result<()>, tokio::task::JoinError>) -> BridgeResult<()> {
    result
        .map_err(|error| BridgeError::new(ErrorCode::Io, error.to_string(), false))?
        .map_err(BridgeError::io)
}

async fn finish_stdin_bounded(mut task: JoinHandle<std::io::Result<()>>) -> BridgeResult<()> {
    match timeout(DRAIN_GRACE, &mut task).await {
        Ok(result) => joined_stdin(result),
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(BridgeError::new(
                ErrorCode::Io,
                "SSH stdin writer did not stop after termination",
                false,
            ))
        }
    }
}

fn joined_capture(
    result: Result<BridgeResult<ChildCaptured>, tokio::task::JoinError>,
) -> BridgeResult<ChildCaptured> {
    result.map_err(|error| BridgeError::new(ErrorCode::Io, error.to_string(), false))?
}

fn joined_wait(
    result: Result<std::io::Result<ExitStatus>, tokio::task::JoinError>,
) -> BridgeResult<ExitStatus> {
    result
        .map_err(|error| BridgeError::new(ErrorCode::Io, error.to_string(), false))?
        .map_err(BridgeError::io)
}

async fn finish_wait(task: JoinHandle<std::io::Result<ExitStatus>>) -> BridgeResult<ExitStatus> {
    joined_wait(task.await)
}

async fn finish_capture_bounded(
    mut task: JoinHandle<BridgeResult<ChildCaptured>>,
) -> BridgeResult<ChildCaptured> {
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

async fn terminate_process_group(process_group: i32) {
    signal_process_group(process_group, libc::SIGTERM);
    tokio::time::sleep(TERM_GRACE).await;
    signal_process_group(process_group, libc::SIGKILL);
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

#[cfg(test)]
mod tests {
    use super::{capability_probe_command, render_fixed_command, render_remote_command};
    use crate::capability::{ShellKind, parse_probe_output};
    use crate::error::ErrorCode;
    use crate::path::RemotePath;

    #[test]
    fn capability_probe_command_binds_hostile_root_as_positional_one() {
        let filesystem = tempfile::TempDir::new().unwrap();
        for component in ["quote'root", "line\nroot", "-leading-root"] {
            let root = filesystem.path().join(component);
            std::fs::create_dir(&root).unwrap();
            let root = root.to_str().unwrap();
            let command = capability_probe_command(root).unwrap();
            let scratch = tempfile::TempDir::new().unwrap();
            let output = std::process::Command::new("/bin/sh")
                .args(["-c", &command])
                .env("TMPDIR", scratch.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "root={root:?}\ncommand={command:?}\nstderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
            let expected = RemotePath::resolve(root, ".").unwrap();
            let capability = parse_probe_output(&output.stdout, &expected).unwrap();
            assert_eq!(capability.physical_root, root);
        }
    }

    #[test]
    fn remote_timeout_uses_gnu_decimal_seconds() {
        let command = render_remote_command("exit 0", &ShellKind::PosixSh, true, 123).unwrap();
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &command])
            .env("PATH", "/usr/bin")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "command={command:?}\nstatus={:?}\nstderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            command,
            "exec timeout --signal=TERM --kill-after=1s 0.123s sh -c 'exit 0'"
        );
        assert_eq!(
            render_remote_command("exit 0", &ShellKind::PosixSh, true, 1000).unwrap(),
            "exec timeout --signal=TERM --kill-after=1s 1.000s sh -c 'exit 0'"
        );
        assert_eq!(
            render_remote_command("exit 0", &ShellKind::PosixSh, true, u64::MAX).unwrap(),
            "exec timeout --signal=TERM --kill-after=1s 18446744073709551.615s sh -c 'exit 0'"
        );
        assert_eq!(
            render_remote_command("exit 0", &ShellKind::PosixSh, true, 0)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn fixed_runner_render_uses_static_script_and_positional_values() {
        let rendered = render_fixed_command(
            "printf '%s\\0' \"$@\"",
            &[
                "quote'".to_owned(),
                "line\n$()`".to_owned(),
                "-x".to_owned(),
            ],
        )
        .unwrap();
        assert!(rendered.starts_with("exec sh -c "));
        assert!(rendered.contains(" codex-ssh-bridge-op "));
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &rendered])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"quote'\0line\n$()`\0-x\0");
    }
}
