#![allow(
    clippy::result_large_err,
    reason = "Task 1 fixes BridgeResult<T> to an inline BridgeError representation"
)]

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::ssh::RuntimePaths;
use crate::{MAX_FRAME_BYTES, MAX_OUTPUT_BYTES, MAX_READ_BYTES};

const SPILL_THRESHOLD_BYTES: u64 = 256 * 1024;
const DEFAULT_TTL: Duration = Duration::from_secs(10 * 60);
const READ_BUFFER_BYTES: usize = 64 * 1024;
const UNKNOWN_REFERENCE: &str = "output reference is unknown or expired";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutputReference(String);

impl OutputReference {
    pub fn parse(value: &str) -> BridgeResult<Self> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(BridgeError::invalid_argument(UNKNOWN_REFERENCE));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPage {
    pub bytes: Vec<u8>,
    pub offset: u64,
    pub next_offset: u64,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPreview {
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
    pub bytes_seen: u64,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StderrSignals {
    pub(crate) host_key: bool,
    pub(crate) authentication: bool,
    pub(crate) connect_timeout: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedOutput {
    pub stdout: OutputPreview,
    pub stderr: OutputPreview,
    pub reference: Option<OutputReference>,
    pub aggregate_bytes: u64,
    pub(crate) stderr_signals: StderrSignals,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureLimits {
    pub preview_bytes: usize,
    pub max_output_bytes: u64,
}

#[derive(Debug)]
struct SpoolEntry {
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    stdout_len: u64,
    stderr_len: u64,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct OutputStore {
    spool_directory: tempfile::TempDir,
    ttl: Duration,
    entries: Arc<Mutex<HashMap<String, SpoolEntry>>>,
}

impl OutputStore {
    pub fn new(runtime: &RuntimePaths) -> BridgeResult<Self> {
        Self::with_ttl(runtime, DEFAULT_TTL)
    }

    pub fn with_ttl(runtime: &RuntimePaths, ttl: Duration) -> BridgeResult<Self> {
        if ttl.is_zero() || ttl > DEFAULT_TTL {
            return Err(BridgeError::invalid_argument(
                "output reference TTL must be between one nanosecond and ten minutes",
            ));
        }
        let spool_directory = tempfile::Builder::new()
            .prefix("output-")
            .tempdir_in(runtime.directory())
            .map_err(BridgeError::io)?;
        std::fs::set_permissions(
            spool_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .map_err(BridgeError::io)?;
        Ok(Self {
            spool_directory,
            ttl,
            entries: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn capture<Stdout, Stderr>(
        &self,
        stdout: Stdout,
        stderr: Stderr,
        limits: CaptureLimits,
        cancel: CancellationToken,
    ) -> BridgeResult<CapturedOutput>
    where
        Stdout: AsyncRead + Unpin + Send + 'static,
        Stderr: AsyncRead + Unpin + Send + 'static,
    {
        self.capture_with_limit_signal(stdout, stderr, limits, cancel, CancellationToken::new())
            .await
    }

    pub(crate) async fn capture_with_limit_signal<Stdout, Stderr>(
        &self,
        stdout: Stdout,
        stderr: Stderr,
        limits: CaptureLimits,
        cancel: CancellationToken,
        output_limit: CancellationToken,
    ) -> BridgeResult<CapturedOutput>
    where
        Stdout: AsyncRead + Unpin + Send + 'static,
        Stderr: AsyncRead + Unpin + Send + 'static,
    {
        if limits.preview_bytes == 0
            || limits.preview_bytes > MAX_FRAME_BYTES
            || limits.max_output_bytes == 0
            || limits.max_output_bytes > MAX_OUTPUT_BYTES
        {
            return Err(BridgeError::invalid_argument(
                "output capture limits exceed the compiled bounds",
            ));
        }
        if cancel.is_cancelled() {
            return Err(capture_cancelled(0));
        }

        let (sender, mut receiver) = mpsc::channel(8);
        let mut stdout_task =
            tokio::spawn(drain_stream(stdout, StreamKind::Stdout, sender.clone()));
        let mut stderr_task = tokio::spawn(drain_stream(stderr, StreamKind::Stderr, sender));
        let mut sink = OutputSink::new(limits.preview_bytes, limits.max_output_bytes);
        let mut finished_streams = 0;

        while finished_streams != 2 {
            let event = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    abort_drains(&mut stdout_task, &mut stderr_task).await;
                    sink.cleanup_incomplete();
                    return Err(capture_cancelled(sink.aggregate_bytes));
                }
                event = receiver.recv() => event,
            };
            match event {
                Some(StreamEvent::Bytes { stream, bytes }) => {
                    if let Err(error) = sink
                        .append(self.spool_directory.path(), stream, &bytes)
                        .await
                    {
                        if error.code == ErrorCode::OutputLimit {
                            output_limit.cancel();
                        }
                        abort_drains(&mut stdout_task, &mut stderr_task).await;
                        sink.cleanup_incomplete();
                        return Err(error);
                    }
                }
                Some(StreamEvent::Finished { error: Some(error) }) => {
                    abort_drains(&mut stdout_task, &mut stderr_task).await;
                    sink.cleanup_incomplete();
                    return Err(BridgeError::io(error));
                }
                Some(StreamEvent::Finished { error: None }) => {
                    finished_streams += 1;
                }
                None => break,
            }
        }
        if let Err(error) = stdout_task.await {
            stderr_task.abort();
            let _ = stderr_task.await;
            sink.cleanup_incomplete();
            return Err(join_error(error));
        }
        if let Err(error) = stderr_task.await {
            sink.cleanup_incomplete();
            return Err(join_error(error));
        }
        sink.finish(self).await
    }

    pub async fn read(
        &self,
        reference: &OutputReference,
        stream: StreamKind,
        offset: u64,
        max_bytes: usize,
    ) -> BridgeResult<OutputPage> {
        if !(1..=MAX_READ_BYTES).contains(&max_bytes) {
            return Err(BridgeError::invalid_argument(format!(
                "max_bytes must be between 1 and {MAX_READ_BYTES}"
            )));
        }

        let now = Instant::now();
        let mut entries = self.entries.lock().await;
        let expired = entries
            .get(reference.as_str())
            .is_some_and(|entry| entry.expires_at <= now);
        if expired {
            let entry = entries
                .remove(reference.as_str())
                .expect("entry was present");
            drop(entries);
            remove_entry_files(&entry).await;
            return Err(unknown_reference());
        }
        let Some(entry) = entries.get(reference.as_str()) else {
            return Err(unknown_reference());
        };
        let (path, length) = match stream {
            StreamKind::Stdout => (entry.stdout_path.clone(), entry.stdout_len),
            StreamKind::Stderr => (entry.stderr_path.clone(), entry.stderr_len),
        };
        drop(entries);

        if offset > length {
            return Err(BridgeError::invalid_argument(
                "output offset exceeds stream length",
            ));
        }
        let wanted = (length - offset).min(max_bytes as u64) as usize;
        let mut bytes = vec![0; wanted];
        if wanted != 0 {
            let mut file = tokio::fs::File::open(path)
                .await
                .map_err(|_| unknown_reference())?;
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(BridgeError::io)?;
            file.read_exact(&mut bytes).await.map_err(BridgeError::io)?;
        }
        let next_offset = offset + bytes.len() as u64;
        Ok(OutputPage {
            bytes,
            offset,
            next_offset,
            eof: next_offset == length,
        })
    }

    pub(crate) async fn discard(&self, captured: &CapturedOutput) {
        let Some(reference) = &captured.reference else {
            return;
        };
        let entry = self.entries.lock().await.remove(reference.as_str());
        if let Some(entry) = entry {
            remove_entry_files(&entry).await;
        }
    }
}

fn join_error(error: tokio::task::JoinError) -> BridgeError {
    BridgeError::new(
        ErrorCode::Io,
        format!("output drain task failed: {error}"),
        false,
    )
}

fn unknown_reference() -> BridgeError {
    BridgeError::invalid_argument(UNKNOWN_REFERENCE)
}

async fn remove_entry_files(entry: &SpoolEntry) {
    let _ = tokio::fs::remove_file(&entry.stdout_path).await;
    let _ = tokio::fs::remove_file(&entry.stderr_path).await;
}

enum StreamEvent {
    Bytes { stream: StreamKind, bytes: Vec<u8> },
    Finished { error: Option<io::Error> },
}

async fn drain_stream<R>(mut reader: R, stream: StreamKind, sender: mpsc::Sender<StreamEvent>)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0; READ_BUFFER_BYTES];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => {
                let _ = sender.send(StreamEvent::Finished { error: None }).await;
                return;
            }
            Ok(count) => {
                if sender
                    .send(StreamEvent::Bytes {
                        stream,
                        bytes: buffer[..count].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(error) => {
                let _ = sender
                    .send(StreamEvent::Finished { error: Some(error) })
                    .await;
                return;
            }
        }
    }
}

async fn abort_drains(
    stdout: &mut tokio::task::JoinHandle<()>,
    stderr: &mut tokio::task::JoinHandle<()>,
) {
    stdout.abort();
    stderr.abort();
    let _ = stdout.await;
    let _ = stderr.await;
}

fn capture_cancelled(bytes_seen: u64) -> BridgeError {
    let mut error = BridgeError::new(ErrorCode::Cancelled, "output capture was cancelled", false);
    error.details.bytes_seen = Some(bytes_seen);
    error
}

struct OutputSink {
    max_output_bytes: u64,
    aggregate_bytes: u64,
    stdout: PreviewSink,
    stderr: PreviewSink,
    retained: RetainedOutput,
    stderr_scanner: DiagnosticScanner,
}

impl OutputSink {
    fn new(preview_bytes: usize, max_output_bytes: u64) -> Self {
        // The aggregate budget is deterministically divided between streams,
        // then each stream allocation is divided between its head and tail.
        let stdout_budget = preview_bytes / 2;
        let stderr_budget = preview_bytes - stdout_budget;
        Self {
            max_output_bytes,
            aggregate_bytes: 0,
            stdout: PreviewSink::new(stdout_budget),
            stderr: PreviewSink::new(stderr_budget),
            retained: RetainedOutput::Memory {
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            stderr_scanner: DiagnosticScanner::default(),
        }
    }

    async fn append(
        &mut self,
        spool_directory: &Path,
        stream: StreamKind,
        bytes: &[u8],
    ) -> BridgeResult<()> {
        let remaining = self.max_output_bytes - self.aggregate_bytes;
        if bytes.len() as u64 > remaining {
            let allowed = remaining as usize;
            if allowed != 0 {
                self.append_allowed(spool_directory, stream, &bytes[..allowed])
                    .await?;
            }
            self.aggregate_bytes = self.max_output_bytes + 1;
            self.cleanup_incomplete();
            let mut error = BridgeError::new(
                ErrorCode::OutputLimit,
                "command output exceeded the configured limit",
                false,
            );
            error.details.bytes_seen = Some(self.aggregate_bytes);
            return Err(error);
        }
        self.append_allowed(spool_directory, stream, bytes).await
    }

    async fn append_allowed(
        &mut self,
        spool_directory: &Path,
        stream: StreamKind,
        bytes: &[u8],
    ) -> BridgeResult<()> {
        if stream == StreamKind::Stderr {
            self.stderr_scanner.push(bytes);
        }
        match stream {
            StreamKind::Stdout => self.stdout.push(bytes),
            StreamKind::Stderr => self.stderr.push(bytes),
        }

        let next_aggregate = self.aggregate_bytes + bytes.len() as u64;
        if next_aggregate > SPILL_THRESHOLD_BYTES
            && matches!(self.retained, RetainedOutput::Memory { .. })
        {
            self.start_spooling(spool_directory).await?;
        }
        self.retained.write(stream, bytes).await?;
        self.aggregate_bytes = next_aggregate;
        Ok(())
    }

    async fn start_spooling(&mut self, directory: &Path) -> BridgeResult<()> {
        let (stdout_bytes, stderr_bytes) = match std::mem::replace(
            &mut self.retained,
            RetainedOutput::Memory {
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
        ) {
            RetainedOutput::Memory { stdout, stderr } => (stdout, stderr),
            retained @ RetainedOutput::Spool(_) => {
                self.retained = retained;
                return Ok(());
            }
        };
        let mut spool = create_spool(directory)?;
        spool
            .stdout
            .write_all(&stdout_bytes)
            .await
            .map_err(BridgeError::io)?;
        spool
            .stderr
            .as_mut()
            .expect("completed pending spool")
            .write_all(&stderr_bytes)
            .await
            .map_err(BridgeError::io)?;
        self.retained = RetainedOutput::Spool(Box::new(spool));
        Ok(())
    }

    fn cleanup_incomplete(&mut self) {
        if matches!(self.retained, RetainedOutput::Spool(_)) {
            self.retained = RetainedOutput::Memory {
                stdout: Vec::new(),
                stderr: Vec::new(),
            };
        }
    }

    async fn finish(mut self, store: &OutputStore) -> BridgeResult<CapturedOutput> {
        self.stderr_scanner.finish_pending_line();
        let reference = match &mut self.retained {
            RetainedOutput::Memory { .. } => None,
            RetainedOutput::Spool(spool) => {
                spool.stdout.flush().await.map_err(BridgeError::io)?;
                spool
                    .stderr
                    .as_mut()
                    .expect("completed pending spool")
                    .flush()
                    .await
                    .map_err(BridgeError::io)?;
                let token = spool.token.clone();
                let reference = OutputReference(token.clone());
                let expires_at = Instant::now() + store.ttl;
                store.entries.lock().await.insert(
                    token.clone(),
                    SpoolEntry {
                        stdout_path: spool.stdout_path.clone(),
                        stderr_path: spool.stderr_path.clone(),
                        stdout_len: self.stdout.bytes_seen,
                        stderr_len: self.stderr.bytes_seen,
                        expires_at,
                    },
                );
                spool.armed = false;
                schedule_expiry(Arc::clone(&store.entries), token, expires_at);
                Some(reference)
            }
        };
        Ok(CapturedOutput {
            stdout: self.stdout.finish(),
            stderr: self.stderr.finish(),
            reference,
            aggregate_bytes: self.aggregate_bytes,
            stderr_signals: self.stderr_scanner.signals,
        })
    }
}

fn schedule_expiry(
    entries: Arc<Mutex<HashMap<String, SpoolEntry>>>,
    token: String,
    expires_at: Instant,
) {
    tokio::spawn(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(expires_at)).await;
        let entry = {
            let mut entries = entries.lock().await;
            if entries
                .get(&token)
                .is_some_and(|entry| entry.expires_at <= Instant::now())
            {
                entries.remove(&token)
            } else {
                None
            }
        };
        if let Some(entry) = entry {
            remove_entry_files(&entry).await;
        }
    });
}

struct PreviewSink {
    head_capacity: usize,
    tail_capacity: usize,
    head: Vec<u8>,
    tail: Vec<u8>,
    bytes_seen: u64,
}

impl PreviewSink {
    fn new(budget: usize) -> Self {
        let head_capacity = budget / 2;
        Self {
            head_capacity,
            tail_capacity: budget - head_capacity,
            head: Vec::with_capacity(head_capacity),
            tail: Vec::with_capacity(budget - head_capacity),
            bytes_seen: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.bytes_seen += bytes.len() as u64;
        let head_needed = self.head_capacity - self.head.len();
        let head_count = head_needed.min(bytes.len());
        self.head.extend_from_slice(&bytes[..head_count]);
        let remaining = &bytes[head_count..];
        if self.tail_capacity == 0 || remaining.is_empty() {
            return;
        }
        if remaining.len() >= self.tail_capacity {
            self.tail.clear();
            self.tail
                .extend_from_slice(&remaining[remaining.len() - self.tail_capacity..]);
            return;
        }
        let excess = self
            .tail
            .len()
            .saturating_add(remaining.len())
            .saturating_sub(self.tail_capacity);
        if excess != 0 {
            self.tail.drain(..excess);
        }
        self.tail.extend_from_slice(remaining);
    }

    fn finish(self) -> OutputPreview {
        let retained = self.head.len() + self.tail.len();
        OutputPreview {
            head: self.head,
            tail: self.tail,
            bytes_seen: self.bytes_seen,
            truncated: self.bytes_seen > retained as u64,
        }
    }
}

enum RetainedOutput {
    Memory { stdout: Vec<u8>, stderr: Vec<u8> },
    Spool(Box<PendingSpool>),
}

impl RetainedOutput {
    async fn write(&mut self, stream: StreamKind, bytes: &[u8]) -> BridgeResult<()> {
        match (self, stream) {
            (Self::Memory { stdout, .. }, StreamKind::Stdout) => stdout.extend_from_slice(bytes),
            (Self::Memory { stderr, .. }, StreamKind::Stderr) => stderr.extend_from_slice(bytes),
            (Self::Spool(spool), StreamKind::Stdout) => {
                spool
                    .stdout
                    .write_all(bytes)
                    .await
                    .map_err(BridgeError::io)?;
            }
            (Self::Spool(spool), StreamKind::Stderr) => {
                spool
                    .stderr
                    .as_mut()
                    .expect("completed pending spool")
                    .write_all(bytes)
                    .await
                    .map_err(BridgeError::io)?;
            }
        }
        Ok(())
    }
}

struct PendingSpool {
    token: String,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    stdout: tokio::fs::File,
    stderr: Option<tokio::fs::File>,
    armed: bool,
}

impl Drop for PendingSpool {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.stdout_path);
            if self.stderr.is_some() {
                let _ = std::fs::remove_file(&self.stderr_path);
            }
        }
    }
}

fn create_spool(directory: &Path) -> BridgeResult<PendingSpool> {
    loop {
        let token = random_token();
        let stdout_path = directory.join(format!("{token}.stdout"));
        let stderr_path = directory.join(format!("{token}.stderr"));
        let stdout = match create_private_file(&stdout_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(BridgeError::io(error)),
        };
        let mut spool = PendingSpool {
            token,
            stdout_path,
            stderr_path,
            stdout: tokio::fs::File::from_std(stdout),
            stderr: None,
            armed: true,
        };
        let stderr = match create_private_file(&spool.stderr_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                drop(spool);
                continue;
            }
            Err(error) => return Err(BridgeError::io(error)),
        };
        spool.stderr = Some(tokio::fs::File::from_std(stderr));
        return Ok(spool);
    }
}

fn create_private_file(path: &Path) -> io::Result<std::fs::File> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

fn random_token() -> String {
    let random: [u8; 16] = rand::random();
    let mut token = String::with_capacity(32);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut token, "{byte:02x}").expect("writing to a String cannot fail");
    }
    token
}

#[derive(Default)]
struct DiagnosticScanner {
    signals: StderrSignals,
    line: Vec<u8>,
    line_overflowed: bool,
}

impl DiagnosticScanner {
    fn push(&mut self, bytes: &[u8]) {
        const MAX_DIAGNOSTIC_LINE_BYTES: usize = 1024;
        for byte in bytes {
            if *byte == b'\n' {
                self.finish_pending_line();
            } else if !self.line_overflowed {
                if self.line.len() == MAX_DIAGNOSTIC_LINE_BYTES {
                    self.line.clear();
                    self.line_overflowed = true;
                } else {
                    self.line.push(*byte);
                }
            }
        }
    }

    fn finish_pending_line(&mut self) {
        if !self.line_overflowed
            && let Ok(line) = std::str::from_utf8(&self.line)
        {
            self.signals.host_key |= is_host_key_diagnostic(line);
            self.signals.authentication |= is_authentication_diagnostic(line);
            self.signals.connect_timeout |= is_connect_timeout_diagnostic(line);
        }
        self.line.clear();
        self.line_overflowed = false;
    }
}

fn is_host_key_diagnostic(line: &str) -> bool {
    if line == "Host key verification failed."
        || line == "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @"
    {
        return true;
    }
    let Some(rest) = line.strip_prefix("No ") else {
        return false;
    };
    let Some((algorithm, rest)) = rest.split_once(" host key is known for ") else {
        return false;
    };
    let Some(host) = rest.strip_suffix(" and you have requested strict checking.") else {
        return false;
    };
    matches!(algorithm, "ED25519" | "RSA" | "ECDSA") && is_single_diagnostic_field(host)
}

fn is_authentication_diagnostic(line: &str) -> bool {
    let Some((identity, methods)) = line.split_once(": Permission denied (") else {
        return false;
    };
    let Some(methods) = methods.strip_suffix(").") else {
        return false;
    };
    let Some((user, host)) = identity.split_once('@') else {
        return false;
    };
    is_single_diagnostic_field(user)
        && is_single_diagnostic_field(host)
        && methods.split(',').all(|method| {
            matches!(
                method,
                "publickey" | "password" | "keyboard-interactive" | "hostbased" | "gssapi-with-mic"
            )
        })
}

fn is_connect_timeout_diagnostic(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("ssh: connect to host ") else {
        return false;
    };
    let Some((destination, reason)) = rest.rsplit_once(": ") else {
        return false;
    };
    let Some((host, port)) = destination.rsplit_once(" port ") else {
        return false;
    };
    is_single_diagnostic_field(host)
        && port.parse::<u16>().is_ok_and(|port| port != 0)
        && matches!(reason, "Connection timed out" | "Operation timed out")
}

fn is_single_diagnostic_field(value: &str) -> bool {
    !value.is_empty()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
}

#[cfg(test)]
mod tests {
    use super::{PendingSpool, create_private_file, create_spool};

    #[test]
    fn dropping_an_unregistered_spool_removes_both_files() {
        let directory = tempfile::TempDir::new().unwrap();
        let spool = create_spool(directory.path()).unwrap();
        let stdout_path = spool.stdout_path.clone();
        let stderr_path = spool.stderr_path.clone();
        assert!(stdout_path.exists());
        assert!(stderr_path.exists());

        drop(spool);

        assert!(!stdout_path.exists());
        assert!(!stderr_path.exists());
    }

    #[test]
    fn dropping_a_partial_spool_preserves_an_unowned_stderr_collision() {
        let directory = tempfile::TempDir::new().unwrap();
        let stdout_path = directory.path().join("partial.stdout");
        let stderr_path = directory.path().join("partial.stderr");
        let stdout = create_private_file(&stdout_path).unwrap();
        std::fs::write(&stderr_path, b"pre-existing sentinel").unwrap();
        let spool = PendingSpool {
            token: "partial".to_owned(),
            stdout_path: stdout_path.clone(),
            stderr_path: stderr_path.clone(),
            stdout: tokio::fs::File::from_std(stdout),
            stderr: None,
            armed: true,
        };

        drop(spool);

        assert!(!stdout_path.exists());
        assert_eq!(
            std::fs::read(&stderr_path).unwrap(),
            b"pre-existing sentinel"
        );
    }
}
