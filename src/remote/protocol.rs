use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::capability::{ShellKind, ShellSelection};
use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{InternalCapturedOutput, StreamKind};

use super::{
    EncodedValue, EntryError, EntryErrorCode, RemoteContext, RemoteFileKind, ShellMetadata,
    ShellName, ValueEncoding,
};

pub(super) fn encode_bytes(bytes: &[u8]) -> EncodedValue {
    match std::str::from_utf8(bytes)
        .ok()
        .filter(|_| !bytes.contains(&0))
    {
        Some(value) => EncodedValue {
            encoding: ValueEncoding::Utf8,
            value: value.to_owned(),
        },
        None => EncodedValue {
            encoding: ValueEncoding::Base64,
            value: STANDARD.encode(bytes),
        },
    }
}

pub(super) fn shell_metadata(shell: &ShellKind, fallback: bool) -> ShellMetadata {
    match shell {
        ShellKind::Bash { version } => ShellMetadata {
            kind: ShellName::Bash,
            version: Some(version.clone()),
            fallback,
        },
        ShellKind::PosixSh => ShellMetadata {
            kind: ShellName::Sh,
            version: None,
            fallback,
        },
        ShellKind::Login => ShellMetadata {
            kind: ShellName::Login,
            version: None,
            fallback,
        },
    }
}

pub(super) fn shell_selection_metadata(shell: &ShellSelection) -> ShellMetadata {
    shell_metadata(&shell.shell, shell.fallback)
}

pub(super) fn context(
    host: String,
    physical_root: String,
    shell: &ShellSelection,
) -> RemoteContext {
    RemoteContext {
        remote: true,
        host,
        physical_root,
        shell: shell_selection_metadata(shell),
    }
}

pub(super) async fn read_stream(
    output: &InternalCapturedOutput,
    stream: StreamKind,
    maximum: usize,
) -> BridgeResult<Vec<u8>> {
    let expected = match stream {
        StreamKind::Stdout => output.stdout_len,
        StreamKind::Stderr => output.stderr_len,
    };
    if expected > maximum as u64 {
        return Err(protocol_error("fixed stream exceeded its protocol bound"));
    }
    let capacity =
        usize::try_from(expected).map_err(|_| protocol_error("fixed stream length is invalid"))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut offset = 0;
    loop {
        let page = output.read(stream, offset, 64 * 1024).await?;
        bytes.extend_from_slice(&page.bytes);
        offset = page.next_offset;
        if page.eof {
            break;
        }
    }
    if bytes.len() != capacity {
        return Err(protocol_error("fixed stream length changed while parsing"));
    }
    Ok(bytes)
}

pub(super) fn nul_fields(bytes: &[u8]) -> BridgeResult<Vec<&[u8]>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.last() != Some(&0) {
        return Err(protocol_error("protocol record is not NUL terminated"));
    }
    let fields: Vec<_> = bytes[..bytes.len() - 1].split(|byte| *byte == 0).collect();
    if fields.iter().any(|field| field.is_empty()) {
        return Err(protocol_error("protocol contains an empty field"));
    }
    Ok(fields)
}

pub(super) fn trim_capped_nul_groups(
    bytes: &mut Vec<u8>,
    fields_per_record: usize,
) -> BridgeResult<()> {
    let Some(last_nul) = bytes.iter().rposition(|byte| *byte == 0) else {
        return Err(protocol_error("protocol record is oversized"));
    };
    bytes.truncate(last_nul + 1);
    let field_count = bytes.iter().filter(|byte| **byte == 0).count();
    let keep_fields = field_count - field_count % fields_per_record;
    if keep_fields == 0 {
        return Err(protocol_error("protocol record is oversized"));
    }
    let keep_end = bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == 0)
        .nth(keep_fields - 1)
        .map(|(index, _)| index + 1)
        .ok_or_else(|| protocol_error("protocol record is oversized"))?;
    bytes.truncate(keep_end);
    Ok(())
}

pub(super) fn utf8(field: &[u8]) -> BridgeResult<&str> {
    std::str::from_utf8(field).map_err(|_| protocol_error("protocol metadata is not UTF-8"))
}

pub(super) fn parse_u64(field: &[u8]) -> BridgeResult<u64> {
    utf8(field)?
        .parse()
        .map_err(|_| protocol_error("protocol integer is invalid"))
}

pub(super) fn parse_mode(field: &[u8]) -> BridgeResult<u32> {
    utf8(field)?
        .parse::<u32>()
        .map(|mode| mode & 0o7777)
        .map_err(|_| protocol_error("protocol mode is invalid"))
}

pub(super) fn parse_mtime(field: &[u8]) -> BridgeResult<(i64, u32)> {
    let value = utf8(field)?;
    let (seconds, fraction) = value
        .split_once('.')
        .ok_or_else(|| protocol_error("protocol timestamp is invalid"))?;
    let seconds = seconds
        .parse()
        .map_err(|_| protocol_error("protocol timestamp is invalid"))?;
    let digits: String = fraction
        .bytes()
        .take_while(u8::is_ascii_digit)
        .map(char::from)
        .take(9)
        .collect();
    if digits.is_empty() {
        return Err(protocol_error("protocol timestamp is invalid"));
    }
    let padded = format!("{digits:0<9}");
    let nanos = padded
        .parse()
        .map_err(|_| protocol_error("protocol timestamp is invalid"))?;
    Ok((seconds, nanos))
}

pub(super) fn kind(field: &[u8]) -> BridgeResult<RemoteFileKind> {
    Ok(match field {
        b"f" => RemoteFileKind::File,
        b"d" => RemoteFileKind::Directory,
        b"l" => RemoteFileKind::Symlink,
        b"b" => RemoteFileKind::BlockDevice,
        b"c" => RemoteFileKind::CharacterDevice,
        b"p" => RemoteFileKind::Fifo,
        b"s" => RemoteFileKind::Socket,
        b"o" | b"?" => RemoteFileKind::Other,
        _ => return Err(protocol_error("protocol file kind is invalid")),
    })
}

pub(super) fn entry_error(status: &[u8]) -> BridgeResult<EntryError> {
    Ok(match status {
        b"NOT_FOUND" => EntryError {
            code: EntryErrorCode::NotFound,
            message: "remote path was not found",
        },
        b"PERMISSION_DENIED" => EntryError {
            code: EntryErrorCode::PermissionDenied,
            message: "remote path permission was denied",
        },
        b"INVALID_ARGUMENT" => EntryError {
            code: EntryErrorCode::InvalidArgument,
            message: "remote path is not a regular file",
        },
        b"READ_CONFLICT" => EntryError {
            code: EntryErrorCode::ReadConflict,
            message: "remote file changed while being read",
        },
        _ => return Err(protocol_error("protocol status is invalid")),
    })
}

pub(super) fn protocol_error(message: &'static str) -> BridgeError {
    BridgeError::new(ErrorCode::ProtocolError, message, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_eight_mib_plus_one_capped_frame_keeps_only_complete_groups() {
        let mut bytes = Vec::with_capacity(crate::MAX_FRAME_BYTES + 1);
        while bytes.len() + 10 <= crate::MAX_FRAME_BYTES {
            bytes.extend_from_slice(b"a\0b\0c\0d\0e\0");
        }
        bytes.resize(crate::MAX_FRAME_BYTES + 1, b'x');
        trim_capped_nul_groups(&mut bytes, 5).unwrap();
        assert!(bytes.len() <= crate::MAX_FRAME_BYTES);
        assert_eq!(bytes.iter().filter(|byte| **byte == 0).count() % 5, 0);
        assert_eq!(bytes.last(), Some(&0));
    }
}
