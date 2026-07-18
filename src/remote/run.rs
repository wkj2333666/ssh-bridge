use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio_util::sync::CancellationToken;

use crate::capability::{ShellKind, ShellRequest};
use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{CapturedOutput, OutputPreview};
use crate::path::RemotePath;

use super::{
    EncodedOutputPreview, POSIX_SH_WARNING, RemoteBridge, RemoteRunRequest, RemoteRunResult,
    RunShell, RunStdin, WriteEncoding, protocol,
};

pub(super) async fn run(
    bridge: &RemoteBridge,
    request: RemoteRunRequest,
    cancel: CancellationToken,
) -> BridgeResult<RemoteRunResult> {
    let host = bridge.runner.config().host(&request.host)?;
    if host.profile.read_only {
        return Err(BridgeError::new(
            ErrorCode::ReadOnlyHost,
            "remote host is configured read-only",
            false,
        ));
    }
    if request.command.is_empty() || request.command.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "remote command must be nonempty and contain no NUL",
        ));
    }

    let requested_cwd = request.cwd.as_deref().unwrap_or(".");
    super::validate_path(requested_cwd)?;
    let cwd = RemotePath::resolve(&host.profile.root, requested_cwd)?;
    let stdin = decode_stdin(request.stdin, host.limits.max_write_bytes)?;
    let timeout_ms = request.timeout_ms.unwrap_or(host.limits.command_timeout_ms);
    if timeout_ms == 0 || timeout_ms > host.limits.command_timeout_ms {
        return Err(BridgeError::invalid_argument(
            "command timeout exceeds the configured limit",
        ));
    }

    let host_name = request.host;
    let result = bridge
        .runner
        .execute(
            crate::ssh::RunRequest {
                host: host_name.clone(),
                command: request.command,
                cwd: cwd.absolute().to_owned(),
                shell: map_shell(request.shell),
                stdin,
                timeout: Duration::from_millis(timeout_ms),
            },
            cancel,
        )
        .await?;
    Ok(convert_result(host_name, result))
}

fn decode_stdin(stdin: Option<RunStdin>, maximum: usize) -> BridgeResult<Option<Vec<u8>>> {
    let Some(stdin) = stdin else {
        return Ok(None);
    };
    let bytes = match stdin.encoding {
        WriteEncoding::Utf8 => stdin.value.into_bytes(),
        WriteEncoding::Base64 => {
            preflight_base64_length(&stdin.value, maximum)?;
            STANDARD.decode(stdin.value.as_bytes()).map_err(|_| {
                BridgeError::invalid_argument("stdin is not canonical standard Base64")
            })?
        }
    };
    if bytes.len() > maximum {
        return Err(BridgeError::new(
            ErrorCode::RequestTooLarge,
            "command input exceeds the configured limit",
            false,
        ));
    }
    Ok(Some(bytes))
}

fn preflight_base64_length(value: &str, maximum: usize) -> BridgeResult<()> {
    if value.is_empty() {
        return Ok(());
    }
    if !value.len().is_multiple_of(4) {
        return Err(BridgeError::invalid_argument(
            "stdin is not canonical standard Base64",
        ));
    }
    let padding = value.bytes().rev().take_while(|byte| *byte == b'=').count();
    if padding > 2 || value.as_bytes()[..value.len() - padding].contains(&b'=') {
        return Err(BridgeError::invalid_argument(
            "stdin is not canonical standard Base64",
        ));
    }
    let decoded_length = (value.len() / 4)
        .checked_mul(3)
        .and_then(|length| length.checked_sub(padding))
        .ok_or_else(command_input_too_large)?;
    if decoded_length > maximum {
        return Err(command_input_too_large());
    }
    Ok(())
}

fn command_input_too_large() -> BridgeError {
    BridgeError::new(
        ErrorCode::RequestTooLarge,
        "command input exceeds the configured limit",
        false,
    )
}

fn map_shell(shell: RunShell) -> ShellRequest {
    match shell {
        RunShell::Auto => ShellRequest::Auto,
        RunShell::Bash => ShellRequest::Bash,
        RunShell::Sh => ShellRequest::Sh,
        RunShell::Login => ShellRequest::Login,
    }
}

fn convert_result(host: String, result: crate::ssh::RunResult) -> RemoteRunResult {
    let crate::ssh::RunResult {
        status,
        elapsed_ms,
        shell,
        physical_root,
        output,
        remote_process_may_continue,
    } = result;
    let CapturedOutput {
        stdout,
        stderr,
        reference,
        aggregate_bytes,
        ..
    } = output;
    let warnings = if matches!(shell.shell, ShellKind::PosixSh) {
        vec![POSIX_SH_WARNING.to_owned()]
    } else {
        Vec::new()
    };
    RemoteRunResult {
        context: protocol::context(host, physical_root, &shell),
        exit_status: status,
        elapsed_ms,
        stdout: encode_preview(stdout),
        stderr: encode_preview(stderr),
        aggregate_bytes,
        output_ref: reference.map(|reference| reference.as_str().to_owned()),
        remote_process_may_continue,
        warnings,
    }
}

fn encode_preview(preview: OutputPreview) -> EncodedOutputPreview {
    EncodedOutputPreview {
        head: protocol::encode_owned_bytes(preview.head),
        tail: protocol::encode_owned_bytes(preview.tail),
        raw_bytes: preview.bytes_seen,
        truncated: preview.truncated,
    }
}
