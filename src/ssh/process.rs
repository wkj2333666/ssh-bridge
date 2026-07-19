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

use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;

use super::{RuntimePaths, SshPolicy, build_ssh_argv, openssh_connect_timeout_option};
use crate::capability::{
    CAPABILITY_PROBE_SCRIPT, Capability, CapabilityCache, ShellKind, ShellRequest, ShellSelection,
    parse_probe_output, select_shell,
};
use crate::config::{Config, EffectiveLimits, MAX_REMOTE_CONTEXT_ROOT_BYTES};
use crate::error::{
    BridgeError, BridgeResult, ErrorCode, ErrorShellMetadata, attach_available_remote_context,
};
use crate::output::{
    CaptureLimits, CapturedOutput, InternalCapturedOutput, InternalSpoolRegistration, OutputPage,
    OutputProvenance, OutputReference, OutputStore, StderrSignals, StoredProvenance, StreamKind,
};
use crate::path::RemotePath;
use crate::quote::{PreparedShellWord, shell_word};

const DEFAULT_SSH_EXECUTABLE: &str = "/usr/bin/ssh";
const RESOLVED_STDOUT_LIMIT: u64 = 1024 * 1024;
const RESOLVED_STDERR_LIMIT: u64 = 64 * 1024;
const PROBE_OUTPUT_LIMIT: u64 = 1024 * 1024;
const REMOTE_TIMEOUT_RETURN_GRACE: Duration = Duration::from_millis(200);
const TERM_GRACE: Duration = Duration::from_millis(50);
const DRAIN_GRACE: Duration = Duration::from_millis(125);
const ROOT_GUARD_EXIT: i32 = 237;
const ROOT_OBSERVE_PROTOCOL_RESERVE: u64 = 128;

const ROOT_OBSERVE_SCRIPT: &str = r#"set -u
[ "$#" -eq 1 ] || exit 2
cd -- "$1" || exit 3
physical_plus=$(pwd -P && printf x) || exit 3
physical_with_delimiter=${physical_plus%x}
newline='
'
physical_root=${physical_with_delimiter%"$newline"}
identity=$(stat -L --printf='%d:%i' -- . 2>/dev/null) ||
    identity=$(stat -f '%d:%i' . 2>/dev/null) || exit 78
case "$identity" in *[!0-9:]*|:*|*:|*:*:*) exit 78 ;; esac
device=${identity%%:*}
inode=${identity#*:}
printf 'CODEX_SSH_ROOT_OBSERVE=1\000ROOT=%s\000DEVICE=%s\000INODE=%s\000' \
    "$physical_root" "$device" "$inode"
"#;

const ROOT_GUARD_PREFIX: &str = r#"set -u
[ "$#" -ge 4 ] || exit 2
r=$1;p=$2;i=$3:$4
shift 4
cd -- "$r" 2>/dev/null||exit 237
x=$(pwd -P&&printf x)||exit 237
x=${x%x};n='
'
x=${x%"$n"};[ "$x" = "$p" ]||exit 237
x=$(stat -L -c %d:%i -- . 2>/dev/null)||x=$(stat -f %d:%i . 2>/dev/null)||exit 237
[ "$x" = "$i" ]||exit 237
(
"#;

const ROOT_GUARD_SUFFIX: &str = r#"
)
s=$?
[ "$s" -ne 237 ]||exit 236
exit "$s"
"#;

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
    pub cwd: String,
    pub shell: ShellRequest,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub status: i32,
    pub elapsed_ms: u64,
    pub shell: ShellSelection,
    pub physical_root: String,
    pub output: CapturedOutput,
    pub remote_process_may_continue: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixedOperationKind {
    ReadOnly,
    Mutation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootIdentity {
    pub(crate) physical_root: String,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RootedPathInputs {
    pub(crate) argument_indices: &'static [usize],
    pub(crate) stdin_nul_paths: bool,
}

#[derive(Clone)]
pub(crate) struct FixedRunRequest {
    pub kind: FixedOperationKind,
    pub host: String,
    pub script: &'static str,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    pub rooted_paths: RootedPathInputs,
    pub expected_root: Option<RootIdentity>,
    pub required_capabilities: &'static [&'static str],
    pub stdout_limit: u64,
    pub stderr_limit: u64,
    pub timeout: Duration,
    pub cleanup: InternalSpoolRegistration,
}

pub(crate) struct FixedRunResult {
    pub capability: Arc<Capability>,
    pub root_identity: RootIdentity,
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
    observed_roots: Mutex<HashMap<String, RootIdentity>>,
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
            observed_roots: Mutex::new(HashMap::new()),
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
        let shell = select_shell(&capability, request.shell).map_err(|mut error| {
            attach_available_remote_context(
                &mut error,
                Some(&request.host),
                Some(&capability.physical_root),
                None,
            );
            error
        })?;
        let operation_deadline = Instant::now()
            .checked_add(request.timeout)
            .ok_or_else(|| BridgeError::invalid_argument("command timeout is too large"))?;
        let observed_root = self
            .observe_root(
                &policy,
                &request.host,
                &root,
                remaining_timeout(operation_deadline)?,
                &cancel,
            )
            .await
            .map_err(|error| {
                attach_selected_context(error, &request.host, &capability.physical_root, &shell)
            })?;
        let trusted_root = RootIdentity {
            physical_root: capability.physical_root.clone(),
            device: capability.root_device,
            inode: capability.root_inode,
        };
        if observed_root != trusted_root {
            return Err(attach_selected_context(
                root_drift_error(FixedOperationKind::Mutation),
                &request.host,
                &observed_root.physical_root,
                &shell,
            ));
        }
        let remote_timeout = !matches!(shell.shell, ShellKind::Login)
            && capability.tools.get("timeout") == Some(&true);
        let prepared = (|| {
            let remaining = remaining_timeout(operation_deadline)?;
            let timeout_ms = u64::try_from(remaining.as_millis())
                .map_err(|_| BridgeError::invalid_argument("command timeout is too large"))?;
            let remote_command = render_remote_command(
                &request.command,
                &reroot_one(&root, &observed_root.physical_root, &request.cwd)?,
                &shell.shell,
                remote_timeout,
                timeout_ms,
                limits.max_frame_bytes,
            )?;
            let remote_command =
                render_root_guarded_command(&root, &observed_root, &remote_command)?;
            ensure_rendered_bound(remote_command.len(), limits.max_frame_bytes)?;
            let local_deadline = if remote_timeout {
                remaining
                    .checked_add(REMOTE_TIMEOUT_RETURN_GRACE)
                    .ok_or_else(|| BridgeError::invalid_argument("command timeout is too large"))?
            } else {
                remaining
            };
            Ok((remote_command, local_deadline))
        })()
        .map_err(|error| {
            attach_selected_context(error, &request.host, &observed_root.physical_root, &shell)
        })?;
        let (remote_command, local_deadline) = prepared;
        let argv = build_ssh_argv(&policy, &request.host, &remote_command);
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
            .await
            .map_err(|error| {
                attach_selected_context(error, &request.host, &observed_root.physical_root, &shell)
            })?;

        let output = outcome.output.into_public().map_err(|error| {
            attach_selected_context(error, &request.host, &observed_root.physical_root, &shell)
        })?;
        self.observed_roots
            .lock()
            .await
            .insert(request.host.clone(), observed_root.clone());
        self.output_store
            .set_provenance(
                &output,
                OutputProvenance {
                    host: request.host.clone(),
                    physical_root: observed_root.physical_root.clone(),
                    shell: shell.clone(),
                },
            )
            .await;
        Ok(RunResult {
            status: outcome.status,
            elapsed_ms: elapsed_ms(operation_started.elapsed()),
            shell,
            physical_root: observed_root.physical_root,
            output,
            remote_process_may_continue: false,
        })
    }

    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    pub(crate) async fn prepare_host(
        &self,
        host: &str,
        cancel: &CancellationToken,
    ) -> BridgeResult<(SshPolicy, Arc<Capability>)> {
        let resolved = self.config.host(host)?;
        let root = resolved.profile.root.clone();
        let limits = resolved.limits;
        let initializer = self.initializer(host).await;
        let initialize_guard = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(cancelled_error(false, 0)),
            guard = initializer.lock() => guard,
        };
        let _reservation = self
            .acquire_operation(host, limits.per_host_concurrency, cancel)
            .await?;
        let prepared = self
            .initialize_host(host, &root, limits.connect_timeout_ms, cancel)
            .await;
        drop(initialize_guard);
        prepared
    }

    pub(crate) async fn cached_capability(&self, host: &str) -> Option<Arc<Capability>> {
        let capability = self.capabilities.get(host).await?;
        let observed = self.observed_roots.lock().await.get(host).cloned();
        match observed {
            None => Some(capability),
            Some(observed) => {
                let mut current = (*capability).clone();
                current.physical_root = observed.physical_root;
                current.root_device = observed.device;
                current.root_inode = observed.inode;
                Some(Arc::new(current))
            }
        }
    }

    pub(crate) async fn invalidate_capability(&self, host: &str) -> bool {
        self.observed_roots.lock().await.remove(host);
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
    ) -> BridgeResult<StoredProvenance> {
        self.output_store.provenance(reference).await
    }

    pub(crate) async fn retain_serialized_detail<T: Serialize + Send + 'static>(
        &self,
        provenance: StoredProvenance,
        owned: T,
        cancel: CancellationToken,
    ) -> BridgeResult<OutputReference> {
        self.output_store
            .retain_serialized_detail(provenance, owned, cancel)
            .await
    }

    pub(crate) async fn execute_fixed_once(
        &self,
        mut request: FixedRunRequest,
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
        let preliminary_command = render_fixed_command(request.script, &request.args)?;
        let transport_bytes = preliminary_command
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
        let shell = ShellSelection {
            shell: ShellKind::PosixSh,
            fallback: false,
        };
        for key in request.required_capabilities {
            if capability.tools.get(*key) != Some(&true) {
                return Err(attach_selected_context(
                    BridgeError::new(
                        ErrorCode::RemoteCapabilityMissing,
                        "remote host lacks a required capability",
                        false,
                    ),
                    &request.host,
                    &capability.physical_root,
                    &shell,
                ));
            }
        }
        let operation_deadline = Instant::now()
            .checked_add(request.timeout)
            .ok_or_else(|| BridgeError::invalid_argument("fixed command timeout is too large"))?;
        let observed_root = self
            .observe_root(
                &policy,
                &request.host,
                &root,
                remaining_timeout(operation_deadline)?,
                &cancel,
            )
            .await
            .map_err(|error| {
                attach_selected_context(error, &request.host, &capability.physical_root, &shell)
            })?;
        let trusted_root = RootIdentity {
            physical_root: capability.physical_root.clone(),
            device: capability.root_device,
            inode: capability.root_inode,
        };
        let expected_root = request
            .expected_root
            .as_ref()
            .unwrap_or(match request.kind {
                FixedOperationKind::ReadOnly => &observed_root,
                FixedOperationKind::Mutation => &trusted_root,
            });
        if &observed_root != expected_root {
            return Err(attach_selected_context(
                root_drift_error(request.kind),
                &request.host,
                &observed_root.physical_root,
                &shell,
            ));
        }
        reroot_fixed_inputs(
            &root,
            &observed_root.physical_root,
            &mut request.args,
            request.stdin.as_mut(),
            request.rooted_paths,
        )?;
        let remote_command =
            render_guarded_fixed_command(&root, &observed_root, request.script, &request.args)?;
        let guarded_transport_bytes = remote_command
            .len()
            .checked_add(request.stdin.as_ref().map_or(0, Vec::len))
            .ok_or_else(rendered_too_large)?;
        ensure_rendered_bound(guarded_transport_bytes, limits.max_frame_bytes)?;
        let outcome = self
            .run_child(
                ChildSpec {
                    argv: build_ssh_argv(&policy, &request.host, &remote_command),
                    stdin: request.stdin,
                    capture_limits: CaptureLimits {
                        preview_bytes: 1,
                        max_output_bytes: capture_limit,
                    },
                    deadline: remaining_timeout(operation_deadline)?,
                    phase: Phase::Fixed { kind: request.kind },
                    internal_registration: Some(request.cleanup),
                },
                &cancel,
                &request.host,
            )
            .await
            .map_err(|error| {
                attach_selected_context(error, &request.host, &observed_root.physical_root, &shell)
            })?;
        let output = outcome
            .output
            .into_internal()
            .map_err(|error| request.kind.after_spawn_error(error))
            .map_err(|error| {
                attach_selected_context(error, &request.host, &observed_root.physical_root, &shell)
            })?;
        if output.stdout_len > request.stdout_limit || output.stderr_len > request.stderr_limit {
            return Err(attach_selected_context(
                request.kind.after_spawn_error(BridgeError::new(
                    ErrorCode::OutputLimit,
                    "fixed output exceeded its stream limit",
                    false,
                )),
                &request.host,
                &observed_root.physical_root,
                &shell,
            ));
        }
        let mut operation_capability = (*capability).clone();
        operation_capability.physical_root = observed_root.physical_root.clone();
        operation_capability.root_device = observed_root.device;
        operation_capability.root_inode = observed_root.inode;
        self.observed_roots
            .lock()
            .await
            .insert(request.host.clone(), observed_root.clone());
        Ok(FixedRunResult {
            capability: Arc::new(operation_capability),
            root_identity: observed_root,
            shell,
            output,
        })
    }

    async fn observe_root(
        &self,
        policy: &SshPolicy,
        host: &str,
        requested_root: &str,
        deadline: Duration,
        cancel: &CancellationToken,
    ) -> BridgeResult<RootIdentity> {
        let command = render_fixed_command(ROOT_OBSERVE_SCRIPT, &[requested_root.to_owned()])?;
        let output_limit = u64::try_from(MAX_REMOTE_CONTEXT_ROOT_BYTES)
            .expect("root bound fits u64")
            .checked_add(ROOT_OBSERVE_PROTOCOL_RESERVE)
            .expect("root protocol bound fits u64");
        let outcome = self
            .run_child(
                ChildSpec {
                    argv: build_ssh_argv(policy, host, &command),
                    stdin: None,
                    capture_limits: CaptureLimits {
                        preview_bytes: usize::try_from(output_limit * 2)
                            .expect("root observation bound fits usize"),
                        max_output_bytes: output_limit,
                    },
                    deadline,
                    phase: Phase::RootObserve,
                    internal_registration: None,
                },
                cancel,
                host,
            )
            .await
            .map_err(|error| {
                if error.code == ErrorCode::RemoteExit && error.details.exit_status == Some(78) {
                    BridgeError::new(
                        ErrorCode::RemoteCapabilityMissing,
                        "remote root identity requires compatible GNU or BSD stat",
                        false,
                    )
                } else {
                    error
                }
            })?;
        let output = outcome.output.into_public()?;
        let stdout = joined_preview(&output.stdout);
        let parsed = parse_root_observation(&stdout);
        self.output_store.discard(&output).await;
        parsed
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
        argv.push(OsString::from("-o"));
        argv.push(openssh_connect_timeout_option(connect_timeout_ms));
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
            .await
            .map_err(|error| {
                if error.code == ErrorCode::RemoteExit && error.details.exit_status == Some(78) {
                    BridgeError::new(
                        ErrorCode::RemoteCapabilityMissing,
                        "remote root identity requires compatible GNU or BSD stat",
                        false,
                    )
                } else {
                    error
                }
            })?;
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
        // From this point the mutation outcome is ambiguous. These setup
        // checks run before any internal spool exists; on an early return the
        // still-owned child is killed by `kill_on_drop`.
        let process_group = child
            .id()
            .ok_or_else(|| BridgeError::new(ErrorCode::Io, "SSH child has no process id", false))
            .map_err(|error| spec.phase.after_spawn_error(error))?
            as i32;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BridgeError::new(ErrorCode::Io, "SSH stdout pipe is missing", false))
            .map_err(|error| spec.phase.after_spawn_error(error))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| BridgeError::new(ErrorCode::Io, "SSH stderr pipe is missing", false))
            .map_err(|error| spec.phase.after_spawn_error(error))?;
        let child_stdin = child.stdin.take();
        let mut stdin_task = tokio::spawn(write_stdin(
            child_stdin,
            spec.stdin,
            spec.phase.accepts_early_stdin_close(),
        ));
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
                        Err(error) => break Stop::InternalError(Box::new(error)),
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
                        Err(error) => Some(Stop::InternalError(Box::new(error.clone()))),
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
                        break Stop::InternalError(Box::new(error));
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
                    Stop::InternalError(error) => *error,
                    Stop::Completed => unreachable!(),
                };
                error.details.host = Some(host.to_owned());
                error.details.elapsed_ms = Some(elapsed_ms(started.elapsed()));
                if stopped_for_output_limit {
                    error.details.bytes_seen = Some(bytes_seen);
                    error.details.remote_process_may_continue = Some(spec.phase.remote_started());
                }
                Err(spec.phase.after_spawn_error(error))
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
        let Some(code) = status.code() else {
            return self.failed_exit(-1, output, phase, host, elapsed).await;
        };
        if code == 0 {
            return Ok(ChildOutcome {
                status: code,
                output,
            });
        }
        if matches!(phase, Phase::Command { .. })
            && code != 255
            && code != ROOT_GUARD_EXIT
            && !(phase.remote_timeout_wrapped() && code == 124)
        {
            return Ok(ChildOutcome {
                status: code,
                output,
            });
        }
        self.failed_exit(code, output, phase, host, elapsed).await
    }

    async fn failed_exit(
        &self,
        code: i32,
        output: ChildCaptured,
        phase: Phase,
        host: &str,
        elapsed: Duration,
    ) -> BridgeResult<ChildOutcome> {
        let root_guard_kind = match phase {
            Phase::Fixed { kind } => Some(kind),
            Phase::Command { .. } => Some(FixedOperationKind::Mutation),
            Phase::Resolve | Phase::Probe | Phase::RootObserve => None,
        };
        if code == ROOT_GUARD_EXIT
            && let Some(kind) = root_guard_kind
        {
            let bytes_seen = output.aggregate_bytes();
            if let ChildCaptured::Public(output) = &output {
                self.output_store.discard(output).await;
            }
            let mut error = root_drift_error(kind);
            error.details.host = Some(host.to_owned());
            error.details.elapsed_ms = Some(elapsed_ms(elapsed));
            error.details.exit_status = Some(code);
            error.details.bytes_seen = Some(bytes_seen);
            return Err(error);
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
        Err(phase.after_spawn_error(error))
    }
}

struct OperationReservation {
    _global: OwnedSemaphorePermit,
    _host: OwnedSemaphorePermit,
}

struct ChildOutcome {
    status: i32,
    output: ChildCaptured,
}

enum ChildCaptured {
    Public(CapturedOutput),
    Internal(InternalCapturedOutput),
}

fn mutation_unknown(mut source: BridgeError) -> BridgeError {
    let mut error = BridgeError::mutation_outcome_unknown();
    error.details.host = source.details.host.take();
    error.details.physical_root = source.details.physical_root.take();
    error.details.shell = source.details.shell.take();
    error.details.elapsed_ms = source.details.elapsed_ms;
    error.details.exit_status = source.details.exit_status;
    error.details.bytes_seen = source.details.bytes_seen;
    error.details.remote_process_may_continue = source.details.remote_process_may_continue;
    error
}

fn error_shell_metadata(shell: &ShellSelection) -> ErrorShellMetadata {
    let (kind, version) = match &shell.shell {
        ShellKind::Bash { version } => ("bash", Some(version.clone())),
        ShellKind::PosixSh => ("sh", None),
        ShellKind::Login => ("login", None),
    };
    ErrorShellMetadata {
        kind: kind.to_owned(),
        version,
        fallback: shell.fallback,
    }
}

fn attach_selected_context(
    mut error: BridgeError,
    host: &str,
    physical_root: &str,
    shell: &ShellSelection,
) -> BridgeError {
    let shell = error_shell_metadata(shell);
    attach_available_remote_context(&mut error, Some(host), Some(physical_root), Some(&shell));
    error
}

impl FixedOperationKind {
    fn after_spawn_error(self, error: BridgeError) -> BridgeError {
        match self {
            Self::ReadOnly => error,
            Self::Mutation => mutation_unknown(error),
        }
    }
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
    RootObserve,
    Command { remote_timeout_wrapped: bool },
    Fixed { kind: FixedOperationKind },
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

    fn after_spawn_error(self, error: BridgeError) -> BridgeError {
        match self {
            Self::Fixed { kind } => kind.after_spawn_error(error),
            Self::Resolve | Self::Probe | Self::RootObserve | Self::Command { .. } => error,
        }
    }

    fn allows_transport_classification(self) -> bool {
        matches!(self, Self::Resolve | Self::Probe | Self::RootObserve)
    }

    fn accepts_early_stdin_close(self) -> bool {
        matches!(
            self,
            Self::Command { .. }
                | Self::Fixed {
                    kind: FixedOperationKind::Mutation
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
            Self::RootObserve => (
                ErrorCode::CommandTimeout,
                "remote root validation timed out",
                false,
            ),
            Self::Command { .. } | Self::Fixed { .. } => {
                (ErrorCode::CommandTimeout, "remote command timed out", false)
            }
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
    InternalError(Box<BridgeError>),
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

fn remaining_timeout(deadline: Instant) -> BridgeResult<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            let mut error = BridgeError::new(
                ErrorCode::CommandTimeout,
                "remote operation exhausted its timeout during root validation",
                false,
            );
            error.details.remote_process_may_continue = Some(false);
            error
        })
}

fn validate_request(request: &RunRequest, limits: EffectiveLimits) -> BridgeResult<()> {
    let timeout_ms = request.timeout.as_millis();
    if timeout_ms == 0 || timeout_ms > u128::from(limits.command_timeout_ms) {
        return Err(BridgeError::invalid_argument(format!(
            "command timeout must be between 1 and {} milliseconds",
            limits.command_timeout_ms
        )));
    }
    if request.command.as_bytes().contains(&0) || request.cwd.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "NUL is not representable in a remote command or cwd",
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
    cwd: &str,
    shell: &ShellKind,
    remote_timeout: bool,
    timeout_ms: u64,
    max_frame_bytes: usize,
) -> BridgeResult<String> {
    if matches!(shell, ShellKind::Login) {
        const PREFIX: &str = "cd -- ";
        const MIDDLE: &str = " || exit 126\n";
        let cwd = PreparedShellWord::new(cwd)?;
        let length =
            checked_rendered_length([PREFIX.len(), cwd.len(), MIDDLE.len(), command.len()])?;
        ensure_rendered_bound(length, max_frame_bytes)?;
        let mut rendered = String::with_capacity(length);
        rendered.push_str(PREFIX);
        cwd.push_to(&mut rendered)?;
        rendered.push_str(MIDDLE);
        rendered.push_str(command);
        debug_assert_eq!(rendered.len(), length);
        return Ok(rendered);
    }
    const BASH_SCRIPT: &str = r#"set -u
[ "$#" -eq 3 ] || exit 2
cd -- "$1" || exit 126
if [ -n "$3" ]; then
    exec timeout --signal=TERM --kill-after=1s "$3" bash --noprofile --norc -c "$2"
fi
exec bash --noprofile --norc -c "$2""#;
    const SH_SCRIPT: &str = r#"set -u
[ "$#" -eq 3 ] || exit 2
cd -- "$1" || exit 126
if [ -n "$3" ]; then
    exec timeout --signal=TERM --kill-after=1s "$3" sh -c "$2"
fi
exec sh -c "$2""#;
    let script = match shell {
        ShellKind::Bash { .. } => BASH_SCRIPT,
        ShellKind::PosixSh => SH_SCRIPT,
        ShellKind::Login => unreachable!(),
    };
    let duration = if remote_timeout {
        format_timeout_duration(timeout_ms)?
    } else {
        String::new()
    };
    const PREFIX: &str = "exec sh -c ";
    const ARG0: &str = " codex-ssh-bridge-run ";
    const SEPARATOR: &str = " ";
    let script = PreparedShellWord::new(script)?;
    let cwd = PreparedShellWord::new(cwd)?;
    let command = PreparedShellWord::new(command)?;
    let duration = PreparedShellWord::new(&duration)?;
    let length = checked_rendered_length([
        PREFIX.len(),
        script.len(),
        ARG0.len(),
        cwd.len(),
        SEPARATOR.len(),
        command.len(),
        SEPARATOR.len(),
        duration.len(),
    ])?;
    ensure_rendered_bound(length, max_frame_bytes)?;
    let mut rendered = String::with_capacity(length);
    rendered.push_str(PREFIX);
    script.push_to(&mut rendered)?;
    rendered.push_str(ARG0);
    cwd.push_to(&mut rendered)?;
    rendered.push_str(SEPARATOR);
    command.push_to(&mut rendered)?;
    rendered.push_str(SEPARATOR);
    duration.push_to(&mut rendered)?;
    debug_assert_eq!(rendered.len(), length);
    Ok(rendered)
}

fn checked_rendered_length(lengths: impl IntoIterator<Item = usize>) -> BridgeResult<usize> {
    lengths.into_iter().try_fold(0usize, |total, length| {
        total.checked_add(length).ok_or_else(rendered_too_large)
    })
}

fn ensure_rendered_bound(length: usize, maximum: usize) -> BridgeResult<()> {
    if length > maximum {
        return Err(rendered_too_large());
    }
    Ok(())
}

fn rendered_too_large() -> BridgeError {
    BridgeError::new(
        ErrorCode::RequestTooLarge,
        "rendered command exceeds the configured frame limit",
        false,
    )
}

pub(crate) fn render_fixed_command(script: &'static str, args: &[String]) -> BridgeResult<String> {
    render_fixed_command_text(script, args)
}

fn render_fixed_command_text(script: &str, args: &[String]) -> BridgeResult<String> {
    let mut command = format!("exec sh -c {} codex-ssh-bridge-op", shell_word(script)?);
    for argument in args {
        command.push(' ');
        command.push_str(&shell_word(argument)?);
    }
    Ok(command)
}

fn render_guarded_fixed_command(
    requested_root: &str,
    identity: &RootIdentity,
    operation: &'static str,
    args: &[String],
) -> BridgeResult<String> {
    render_inlined_root_guard(requested_root, identity, operation, args)
}

fn render_root_guarded_command(
    requested_root: &str,
    identity: &RootIdentity,
    operation: &str,
) -> BridgeResult<String> {
    render_inlined_root_guard(requested_root, identity, operation, &[])
}

fn render_inlined_root_guard(
    requested_root: &str,
    identity: &RootIdentity,
    operation: &str,
    operation_args: &[String],
) -> BridgeResult<String> {
    let mut guarded_args = vec![
        requested_root.to_owned(),
        identity.physical_root.clone(),
        identity.device.to_string(),
        identity.inode.to_string(),
    ];
    guarded_args.extend_from_slice(operation_args);
    let script_length = ROOT_GUARD_PREFIX
        .len()
        .checked_add(operation.len())
        .and_then(|length| length.checked_add(ROOT_GUARD_SUFFIX.len()))
        .ok_or_else(rendered_too_large)?;
    let mut script = String::with_capacity(script_length);
    script.push_str(ROOT_GUARD_PREFIX);
    script.push_str(operation);
    script.push_str(ROOT_GUARD_SUFFIX);
    debug_assert_eq!(script.len(), script_length);
    render_fixed_command_text(&script, &guarded_args)
}

fn parse_root_observation(output: &[u8]) -> BridgeResult<RootIdentity> {
    let fields = output.split(|byte| *byte == 0).collect::<Vec<_>>();
    if fields.len() != 5 || !fields[4].is_empty() || fields[0] != b"CODEX_SSH_ROOT_OBSERVE=1" {
        return Err(root_observation_error());
    }
    let root = fields[1]
        .strip_prefix(b"ROOT=")
        .ok_or_else(root_observation_error)?;
    let device = fields[2]
        .strip_prefix(b"DEVICE=")
        .ok_or_else(root_observation_error)?;
    let inode = fields[3]
        .strip_prefix(b"INODE=")
        .ok_or_else(root_observation_error)?;
    let physical_root = std::str::from_utf8(root).map_err(|_| root_observation_error())?;
    if physical_root.len() > MAX_REMOTE_CONTEXT_ROOT_BYTES || !physical_root.starts_with('/') {
        return Err(root_observation_error());
    }
    let normalized =
        RemotePath::resolve("/", physical_root).map_err(|_| root_observation_error())?;
    if normalized.absolute() != physical_root {
        return Err(root_observation_error());
    }
    Ok(RootIdentity {
        physical_root: physical_root.to_owned(),
        device: parse_root_observation_u64(device)?,
        inode: parse_root_observation_u64(inode)?,
    })
}

fn parse_root_observation_u64(value: &[u8]) -> BridgeResult<u64> {
    if value.is_empty() || value.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(root_observation_error());
    }
    std::str::from_utf8(value)
        .map_err(|_| root_observation_error())?
        .parse()
        .map_err(|_| root_observation_error())
}

fn root_observation_error() -> BridgeError {
    BridgeError::new(
        ErrorCode::ProtocolError,
        "remote root observation is invalid",
        false,
    )
}

fn reroot_fixed_inputs(
    configured_root: &str,
    physical_root: &str,
    args: &mut [String],
    stdin: Option<&mut Vec<u8>>,
    rooted: RootedPathInputs,
) -> BridgeResult<()> {
    let configured = RemotePath::resolve(configured_root, ".")?;
    for index in rooted.argument_indices {
        let argument = args.get_mut(*index).ok_or_else(|| {
            BridgeError::new(
                ErrorCode::ProtocolError,
                "fixed rooted argument index is invalid",
                false,
            )
        })?;
        *argument = reroot_one(configured.absolute(), physical_root, argument)?;
    }
    if rooted.stdin_nul_paths {
        let stdin = stdin.ok_or_else(|| {
            BridgeError::new(
                ErrorCode::ProtocolError,
                "fixed rooted stdin is missing",
                false,
            )
        })?;
        if stdin.last() != Some(&0) {
            return Err(BridgeError::new(
                ErrorCode::ProtocolError,
                "fixed rooted stdin is not NUL terminated",
                false,
            ));
        }
        let mut rewritten = Vec::with_capacity(stdin.len());
        for field in stdin[..stdin.len() - 1].split(|byte| *byte == 0) {
            let path = std::str::from_utf8(field).map_err(|_| {
                BridgeError::new(
                    ErrorCode::ProtocolError,
                    "fixed rooted stdin path is not UTF-8",
                    false,
                )
            })?;
            rewritten.extend_from_slice(
                reroot_one(configured.absolute(), physical_root, path)?.as_bytes(),
            );
            rewritten.push(0);
        }
        *stdin = rewritten;
    }
    Ok(())
}

fn reroot_one(configured_root: &str, physical_root: &str, path: &str) -> BridgeResult<String> {
    let relative = if path == configured_root {
        ""
    } else if configured_root == "/" {
        path.strip_prefix('/').ok_or_else(rooted_path_error)?
    } else {
        path.strip_prefix(configured_root)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .ok_or_else(rooted_path_error)?
    };
    if relative.is_empty() {
        Ok(physical_root.to_owned())
    } else if physical_root == "/" {
        Ok(format!("/{relative}"))
    } else {
        Ok(format!("{physical_root}/{relative}"))
    }
}

fn rooted_path_error() -> BridgeError {
    BridgeError::new(
        ErrorCode::ProtocolError,
        "fixed rooted path escaped the configured root",
        false,
    )
}

fn root_drift_error(kind: FixedOperationKind) -> BridgeError {
    match kind {
        FixedOperationKind::ReadOnly => BridgeError::read_conflict(),
        FixedOperationKind::Mutation => {
            let mut error = BridgeError::new(
                ErrorCode::WriteConflict,
                "remote physical root changed after trust was established",
                false,
            );
            error.details.mutation_may_have_applied = Some(false);
            error
        }
    }
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
    accepts_early_close: bool,
) -> std::io::Result<()> {
    if let Some(mut stdin) = stdin.take() {
        if let Some(bytes) = bytes
            && let Err(error) = stdin.write_all(&bytes).await
        {
            if accepts_early_close && error.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(error);
        }
        if let Err(error) = stdin.shutdown().await {
            if accepts_early_close && error.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(error);
        }
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
    use super::{
        ChildSpec, FixedOperationKind, Phase, RootIdentity, SshRunner, capability_probe_command,
        ensure_rendered_bound, mutation_unknown, render_fixed_command,
        render_guarded_fixed_command, render_remote_command,
    };

    #[test]
    fn final_guarded_transport_is_checked_after_trusted_wrapper_expansion() {
        let original = render_fixed_command("printf %s \"$1\"", &["x".repeat(512)]).unwrap();
        let guarded = render_guarded_fixed_command(
            "/r",
            &RootIdentity {
                physical_root: "/physical/root".to_owned(),
                device: 1,
                inode: 2,
            },
            "printf %s \"$1\"",
            &["x".repeat(512)],
        )
        .unwrap();
        let maximum = guarded.len() - 1;
        assert!(original.len() <= maximum);
        assert_eq!(
            ensure_rendered_bound(guarded.len(), maximum)
                .unwrap_err()
                .code,
            ErrorCode::RequestTooLarge
        );
    }
    use crate::capability::{ShellKind, parse_probe_output};
    use crate::config::{Config, HostProfile};
    use crate::error::{BridgeError, ErrorCode};
    use crate::output::{CaptureLimits, InternalSpoolOwner, OutputStore};
    use crate::path::RemotePath;
    use crate::ssh::RuntimePaths;
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::{Instant, sleep};
    use tokio_util::sync::CancellationToken;

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
        let command =
            render_remote_command("exit 0", "/", &ShellKind::PosixSh, true, 123, usize::MAX)
                .unwrap();
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
        assert!(command.contains(" codex-ssh-bridge-run '/' 'exit 0' '0.123s'"));
        assert_eq!(
            render_remote_command("exit 0", "/", &ShellKind::PosixSh, true, 1000, usize::MAX,)
                .unwrap()
                .rsplit(' ')
                .next(),
            Some("'1.000s'")
        );
        assert_eq!(
            render_remote_command(
                "exit 0",
                "/",
                &ShellKind::PosixSh,
                true,
                u64::MAX,
                usize::MAX,
            )
            .unwrap()
            .rsplit(' ')
            .next(),
            Some("'18446744073709551.615s'")
        );
        assert_eq!(
            render_remote_command("exit 0", "/", &ShellKind::PosixSh, true, 0, usize::MAX,)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task78_run_render_accepts_exact_bound_rejects_minus_one_without_quote_expansion() {
        let command = "'".repeat(4 * 1024);
        let rendered = render_remote_command(
            &command,
            "/srv/quote'root",
            &ShellKind::PosixSh,
            false,
            1000,
            usize::MAX,
        )
        .unwrap();
        let exact = rendered.len();
        assert!(rendered.capacity() >= exact);
        assert_eq!(
            render_remote_command(
                &command,
                "/srv/quote'root",
                &ShellKind::PosixSh,
                false,
                1000,
                exact,
            )
            .unwrap(),
            rendered
        );
        assert_eq!(
            render_remote_command(
                &command,
                "/srv/quote'root",
                &ShellKind::PosixSh,
                false,
                1000,
                exact - 1,
            )
            .unwrap_err()
            .code,
            ErrorCode::RequestTooLarge
        );
        let hostile = "'".repeat(crate::MAX_FRAME_BYTES);
        assert_eq!(
            render_remote_command(
                &hostile,
                "/srv/quote'root",
                &ShellKind::PosixSh,
                false,
                1000,
                512,
            )
            .unwrap_err()
            .code,
            ErrorCode::RequestTooLarge
        );
    }

    #[test]
    fn task78_quote_admission_release_rss() {
        run_quote_admission_release_rss();
    }

    fn run_quote_admission_release_rss() {
        const CHILD_ENV: &str = "CODEX_SSH_BRIDGE_QUOTE_RSS_CHILD";
        const TEST_NAME: &str = "ssh::process::tests::task78_quote_admission_release_rss";
        if cfg!(debug_assertions) {
            eprintln!("quote admission RSS assertion is release-only");
            return;
        }
        if std::env::var_os(CHILD_ENV).is_some() {
            quote_admission_rss_child();
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprint!("{stdout}");
        eprint!("{stderr}");
        assert!(output.status.success(), "fresh quote RSS child failed");
        assert!(
            stdout.contains("quote admission release RSS:")
                || stderr.contains("quote admission release RSS:"),
            "fresh quote RSS child did not run the requested test"
        );
    }

    fn quote_admission_rss_child() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        const WORKERS: usize = 5;
        const ROUNDS: usize = 16;
        const RSS_DELTA_CEILING_KIB: u64 = 16 * 1024;

        let commands: Vec<_> = (0..WORKERS)
            .map(|_| Arc::new("'".repeat(crate::MAX_FRAME_BYTES)))
            .collect();
        assert!(
            commands
                .iter()
                .all(|command| command.len() == crate::MAX_FRAME_BYTES)
        );
        let warmed = commands
            .iter()
            .flat_map(|command| command.as_bytes().iter().step_by(4096))
            .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        std::hint::black_box(warmed);

        let start = Arc::new(Barrier::new(WORKERS + 1));
        let finish = Arc::new(Barrier::new(WORKERS + 1));
        let completed = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(WORKERS);
        for command in commands {
            let start = Arc::clone(&start);
            let finish = Arc::clone(&finish);
            let completed = Arc::clone(&completed);
            workers.push(std::thread::spawn(move || {
                start.wait();
                let mut last_error = None;
                for _ in 0..ROUNDS {
                    let error = render_remote_command(
                        &command,
                        "/srv/project",
                        &ShellKind::PosixSh,
                        false,
                        1_000,
                        crate::MAX_FRAME_BYTES,
                    )
                    .unwrap_err();
                    assert_eq!(error.code, ErrorCode::RequestTooLarge);
                    assert_eq!(
                        error.message,
                        "rendered command exceeds the configured frame limit"
                    );
                    last_error = Some(error);
                }
                completed.fetch_add(1, Ordering::Release);
                finish.wait();
                last_error.unwrap().code
            }));
        }

        let baseline = resident_kib_for_rss_test();
        let mut peak = baseline;
        start.wait();
        while completed.load(Ordering::Acquire) != WORKERS {
            peak = peak.max(resident_kib_for_rss_test());
            std::thread::sleep(Duration::from_micros(250));
        }
        for _ in 0..20 {
            peak = peak.max(resident_kib_for_rss_test());
            std::thread::sleep(Duration::from_millis(1));
        }
        finish.wait();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), ErrorCode::RequestTooLarge);
        }
        let delta = peak.saturating_sub(baseline);
        eprintln!(
            "quote admission release RSS: baseline={baseline} KiB peak={peak} KiB delta={delta} KiB ceiling={RSS_DELTA_CEILING_KIB} KiB"
        );
        assert!(
            delta < RSS_DELTA_CEILING_KIB,
            "quote admission RSS baseline={baseline} peak={peak} delta={delta}"
        );
    }

    fn resident_kib_for_rss_test() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse().ok())
            })
            .unwrap()
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

    #[test]
    fn task5_mutation_unknown_is_closed_non_retryable_and_preserves_safe_context() {
        let mut source = BridgeError::new(ErrorCode::RemoteExit, "untrusted detail", true);
        source.details.host = Some("dev".to_owned());
        source.details.elapsed_ms = Some(17);
        source.details.exit_status = Some(255);
        source.details.bytes_seen = Some(23);
        source.details.remote_process_may_continue = Some(true);

        let error = mutation_unknown(source);
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(
            error.message,
            "remote mutation outcome could not be confirmed"
        );
        assert!(!error.retryable);
        assert_eq!(error.details.host.as_deref(), Some("dev"));
        assert_eq!(error.details.elapsed_ms, Some(17));
        assert_eq!(error.details.exit_status, Some(255));
        assert_eq!(error.details.bytes_seen, Some(23));
        assert_eq!(error.details.remote_process_may_continue, Some(true));
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
    }

    fn task5_test_runner(executable: &str) -> (tempfile::TempDir, SshRunner) {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let output = Arc::new(OutputStore::new(&runtime).unwrap());
        let runner = SshRunner::with_executable(
            Arc::new(Config::default()),
            runtime,
            output,
            PathBuf::from(executable),
            BTreeMap::<OsString, OsString>::new(),
        )
        .unwrap();
        (base, runner)
    }

    struct Task5FixedFixture {
        _base: tempfile::TempDir,
        runtime: RuntimePaths,
        runner: Arc<SshRunner>,
    }

    fn task5_fixed_fixture(environment: &[(&str, String)]) -> Task5FixedFixture {
        let base = tempfile::TempDir::new().unwrap();
        let runtime = RuntimePaths::ensure_from_base(base.path()).unwrap();
        let output = Arc::new(OutputStore::new(&runtime).unwrap());
        let mut config = Config::default();
        config.hosts.insert(
            "dev".to_owned(),
            HostProfile {
                root: "/srv/project".to_owned(),
                description: None,
                read_only: false,
                limits: Default::default(),
            },
        );
        let environment = environment
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect();
        let executable =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-ssh.sh");
        let runner = Arc::new(
            SshRunner::with_executable(
                Arc::new(config),
                runtime.clone(),
                output,
                executable,
                environment,
            )
            .unwrap(),
        );
        Task5FixedFixture {
            _base: base,
            runtime,
            runner,
        }
    }

    fn task5_fixed_request(
        kind: FixedOperationKind,
        timeout: Duration,
        cleanup: crate::output::InternalSpoolRegistration,
        stdout_limit: u64,
        stderr_limit: u64,
    ) -> super::FixedRunRequest {
        super::FixedRunRequest {
            kind,
            host: "dev".to_owned(),
            script: "exit 0",
            args: Vec::new(),
            stdin: None,
            rooted_paths: super::RootedPathInputs::default(),
            expected_root: None,
            required_capabilities: &["safe_write"],
            stdout_limit,
            stderr_limit,
            timeout,
            cleanup,
        }
    }

    fn task5_call_count(log: &std::path::Path, marker: &str) -> usize {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|line| *line == marker)
            .count()
    }

    async fn task5_wait_for_call(log: &std::path::Path, marker: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while task5_call_count(log, marker) == 0 {
            assert!(Instant::now() < deadline, "missing {marker} call");
            sleep(Duration::from_millis(5)).await;
        }
    }

    fn task5_internal_spool_file_count(runtime: &RuntimePaths) -> usize {
        std::fs::read_dir(runtime.directory())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .flat_map(|entry| {
                std::fs::read_dir(entry.path())
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
            })
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .count()
    }

    fn task5_child(script: &str, kind: FixedOperationKind, deadline: Duration) -> ChildSpec {
        ChildSpec {
            argv: vec![OsString::from("-c"), OsString::from(script)],
            stdin: None,
            capture_limits: CaptureLimits {
                preview_bytes: 1,
                max_output_bytes: 1024,
            },
            deadline,
            phase: Phase::Fixed { kind },
            internal_registration: None,
        }
    }

    #[tokio::test]
    async fn task5_mutation_phase_marks_only_post_spawn_ambiguity() {
        let (_base, runner) = task5_test_runner("/bin/sh");

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let error = runner
            .run_child(
                task5_child(
                    "exit 0",
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                ),
                &cancelled,
                "dev",
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Cancelled);
        assert_eq!(error.details.mutation_may_have_applied, None);

        let error = runner
            .run_child(
                task5_child(
                    "exit 7",
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                ),
                &CancellationToken::new(),
                "dev",
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.exit_status, Some(7));
        assert_eq!(error.details.mutation_may_have_applied, Some(true));

        let error = runner
            .run_child(
                task5_child(
                    "sleep 1",
                    FixedOperationKind::Mutation,
                    Duration::from_millis(10),
                ),
                &CancellationToken::new(),
                "dev",
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));

        let error = runner
            .run_child(
                task5_child(
                    "exit 7",
                    FixedOperationKind::ReadOnly,
                    Duration::from_secs(1),
                ),
                &CancellationToken::new(),
                "dev",
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::RemoteExit);
        assert_eq!(error.details.mutation_may_have_applied, None);

        let mut ordinary = task5_child(
            "exit 0",
            FixedOperationKind::ReadOnly,
            Duration::from_secs(1),
        );
        ordinary.phase = Phase::Command {
            remote_timeout_wrapped: false,
        };
        ordinary.stdin = Some(vec![b'x'; 4 * 1024 * 1024]);
        runner
            .run_child(ordinary, &CancellationToken::new(), "dev")
            .await
            .unwrap();

        let mut readonly = task5_child(
            "exit 0",
            FixedOperationKind::ReadOnly,
            Duration::from_secs(1),
        );
        readonly.stdin = Some(vec![b'x'; 4 * 1024 * 1024]);
        let error = runner
            .run_child(readonly, &CancellationToken::new(), "dev")
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Io);
        assert_eq!(error.details.mutation_may_have_applied, None);

        let (_missing_base, missing_runner) = task5_test_runner("/no/such/task5-ssh");
        let error = missing_runner
            .run_child(
                task5_child(
                    "exit 0",
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                ),
                &CancellationToken::new(),
                "dev",
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Io);
        assert_eq!(error.details.mutation_may_have_applied, None);
    }

    #[tokio::test]
    async fn task5_execute_fixed_once_maps_only_spawned_mutations_and_never_retries() {
        let logs = tempfile::TempDir::new().unwrap();

        let cached_false_log = logs.path().join("cached-false.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", cached_false_log.display().to_string()),
            ("FAKE_SSH_HAS_SAFE_WRITE", "0".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let error = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                    owner.registration(),
                    16,
                    16,
                ),
                CancellationToken::new(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::RemoteCapabilityMissing);
        assert_eq!(error.details.mutation_may_have_applied, None);
        assert_eq!(task5_call_count(&cached_false_log, "C"), 0);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        let pre_cancel_log = logs.path().join("pre-cancel.log");
        let fixture =
            task5_fixed_fixture(&[("FAKE_SSH_LOG", pre_cancel_log.display().to_string())]);
        let owner = InternalSpoolOwner::new();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                    owner.registration(),
                    16,
                    16,
                ),
                cancel,
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::Cancelled);
        assert_eq!(error.details.mutation_may_have_applied, None);
        assert_eq!(task5_call_count(&pre_cancel_log, "C"), 0);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        let probe_cancel_log = logs.path().join("probe-cancel.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", probe_cancel_log.display().to_string()),
            ("FAKE_SSH_PROBE_SLEEP_SECONDS", "5".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let runner = Arc::clone(&fixture.runner);
            let cancel = cancel.clone();
            let request = task5_fixed_request(
                FixedOperationKind::Mutation,
                Duration::from_secs(1),
                owner.registration(),
                16,
                16,
            );
            async move { runner.execute_fixed_once(request, cancel).await }
        });
        task5_wait_for_call(&probe_cancel_log, "P").await;
        cancel.cancel();
        let error = task.await.unwrap().err().unwrap();
        assert_eq!(error.code, ErrorCode::Cancelled);
        assert_eq!(error.details.mutation_may_have_applied, None);
        assert_eq!(task5_call_count(&probe_cancel_log, "C"), 0);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        for (name, exit_status) in [("exit7", 7), ("status255", 255)] {
            let log = logs.path().join(format!("{name}.log"));
            let fixture = task5_fixed_fixture(&[
                ("FAKE_SSH_LOG", log.display().to_string()),
                ("FAKE_SSH_MODE", "error".to_owned()),
                ("FAKE_SSH_ERROR", "remote".to_owned()),
                ("FAKE_SSH_EXIT_STATUS", exit_status.to_string()),
            ]);
            let owner = InternalSpoolOwner::new();
            let error = fixture
                .runner
                .execute_fixed_once(
                    task5_fixed_request(
                        FixedOperationKind::Mutation,
                        Duration::from_secs(1),
                        owner.registration(),
                        16,
                        64,
                    ),
                    CancellationToken::new(),
                )
                .await
                .err()
                .unwrap();
            assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown, "{name}");
            assert_eq!(error.details.exit_status, Some(exit_status), "{name}");
            assert_eq!(error.details.mutation_may_have_applied, Some(true));
            assert_eq!(task5_call_count(&log, "C"), 1, "{name}");
            drop(owner);
            assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);
        }

        let timeout_log = logs.path().join("timeout.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", timeout_log.display().to_string()),
            ("FAKE_SSH_MODE", "sleep".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "5".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let error = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::Mutation,
                    Duration::from_millis(20),
                    owner.registration(),
                    16,
                    16,
                ),
                CancellationToken::new(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
        assert_eq!(task5_call_count(&timeout_log, "C"), 1);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        let cancel_log = logs.path().join("spawn-cancel.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", cancel_log.display().to_string()),
            ("FAKE_SSH_MODE", "sleep".to_owned()),
            ("FAKE_SSH_SLEEP_SECONDS", "5".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let runner = Arc::clone(&fixture.runner);
            let cancel = cancel.clone();
            let request = task5_fixed_request(
                FixedOperationKind::Mutation,
                Duration::from_secs(5),
                owner.registration(),
                16,
                16,
            );
            async move { runner.execute_fixed_once(request, cancel).await }
        });
        task5_wait_for_call(&cancel_log, "C").await;
        cancel.cancel();
        let error = task.await.unwrap().err().unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
        assert_eq!(task5_call_count(&cancel_log, "C"), 1);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        let overflow_log = logs.path().join("overflow.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", overflow_log.display().to_string()),
            ("FAKE_SSH_MODE", "bytes".to_owned()),
            ("FAKE_SSH_STDOUT_BYTES", "64".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let error = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                    owner.registration(),
                    16,
                    16,
                ),
                CancellationToken::new(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
        assert_eq!(task5_call_count(&overflow_log, "C"), 1);
        drop(owner);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);

        // A closed registration forces internal capture setup to fail after
        // local spawn. The child races that asynchronous setup and may reach
        // the fixture log first, which is precisely why the mutation outcome
        // is unknown. The pending spool is armed and unlinked on drop, and the
        // child remains kill-on-drop if any post-spawn pid/pipe invariant ever
        // fails before the wait task takes ownership.
        let setup_log = logs.path().join("capture-setup.log");
        let fixture = task5_fixed_fixture(&[
            ("FAKE_SSH_LOG", setup_log.display().to_string()),
            ("FAKE_SSH_MODE", "streams".to_owned()),
        ]);
        let owner = InternalSpoolOwner::new();
        let registration = owner.registration();
        drop(owner);
        let error = fixture
            .runner
            .execute_fixed_once(
                task5_fixed_request(
                    FixedOperationKind::Mutation,
                    Duration::from_secs(1),
                    registration,
                    16,
                    16,
                ),
                CancellationToken::new(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
        assert_eq!(error.details.mutation_may_have_applied, Some(true));
        assert!(task5_call_count(&setup_log, "C") <= 1);
        assert_eq!(task5_internal_spool_file_count(&fixture.runtime), 0);
    }
}
