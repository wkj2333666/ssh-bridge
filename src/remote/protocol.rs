use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::capability::{ShellKind, ShellSelection};
use crate::error::{BridgeError, BridgeResult, ErrorCode};
use crate::output::{InternalCapturedOutput, StreamKind};
use crate::ssh::{FixedRunResult, HelperMode};

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

pub(super) fn encode_owned_bytes(bytes: Vec<u8>) -> EncodedValue {
    if bytes.contains(&0) {
        return EncodedValue {
            encoding: ValueEncoding::Base64,
            value: STANDARD.encode(bytes),
        };
    }
    match String::from_utf8(bytes) {
        Ok(value) => EncodedValue {
            encoding: ValueEncoding::Utf8,
            value,
        },
        Err(error) => EncodedValue {
            encoding: ValueEncoding::Base64,
            value: STANDARD.encode(error.into_bytes()),
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
    helper_mode: HelperMode,
) -> RemoteContext {
    RemoteContext {
        remote: true,
        host,
        physical_root,
        shell: shell_selection_metadata(shell),
        helper_mode: Some(helper_mode),
    }
}

const CURSOR_PAGE_BYTES: usize = 64 * 1024;

pub(super) struct SpoolCursor<'a> {
    output: &'a InternalCapturedOutput,
    stream: StreamKind,
    length: u64,
    offset: u64,
    page: Vec<u8>,
    page_index: usize,
    discarded_incomplete: bool,
}

impl<'a> SpoolCursor<'a> {
    pub(super) fn new(
        output: &'a InternalCapturedOutput,
        stream: StreamKind,
        maximum: usize,
    ) -> BridgeResult<Self> {
        let length = match stream {
            StreamKind::Stdout => output.stdout_len,
            StreamKind::Stderr => output.stderr_len,
        };
        if length > maximum as u64 {
            return Err(protocol_error("fixed stream exceeded its protocol bound"));
        }
        Ok(Self {
            output,
            stream,
            length,
            offset: 0,
            page: Vec::new(),
            page_index: 0,
            discarded_incomplete: false,
        })
    }

    pub(super) async fn next_field(&mut self, maximum: usize) -> BridgeResult<Option<Vec<u8>>> {
        self.next_delimited(0, maximum, "protocol record is not NUL terminated", false)
            .await
    }

    pub(super) async fn next_field_capped(
        &mut self,
        maximum: usize,
    ) -> BridgeResult<Option<Vec<u8>>> {
        self.next_delimited(0, maximum, "protocol record is not NUL terminated", true)
            .await
    }

    pub(super) async fn next_line(&mut self, maximum: usize) -> BridgeResult<Option<Vec<u8>>> {
        self.next_delimited(
            b'\n',
            maximum,
            "protocol line is not newline terminated",
            false,
        )
        .await
    }

    pub(super) async fn next_line_capped(
        &mut self,
        maximum: usize,
    ) -> BridgeResult<Option<Vec<u8>>> {
        self.next_delimited(
            b'\n',
            maximum,
            "protocol line is not newline terminated",
            true,
        )
        .await
    }

    async fn next_delimited(
        &mut self,
        delimiter: u8,
        maximum: usize,
        incomplete: &'static str,
        discard_incomplete: bool,
    ) -> BridgeResult<Option<Vec<u8>>> {
        let mut record = Vec::new();
        loop {
            if self.page_index == self.page.len() {
                if self.offset == self.length {
                    if record.is_empty() {
                        return Ok(None);
                    }
                    if discard_incomplete {
                        self.discarded_incomplete = true;
                        return Ok(None);
                    }
                    return Err(protocol_error(incomplete));
                }
                let page = self
                    .output
                    .read(self.stream, self.offset, CURSOR_PAGE_BYTES)
                    .await?;
                if page.bytes.is_empty() && !page.eof {
                    return Err(protocol_error("fixed stream cursor made no progress"));
                }
                self.offset = page.next_offset;
                self.page = page.bytes;
                self.page_index = 0;
                continue;
            }

            let remaining = &self.page[self.page_index..];
            if let Some(relative) = remaining.iter().position(|byte| *byte == delimiter) {
                self.extend_record(&mut record, &remaining[..relative], maximum)?;
                self.page_index += relative + 1;
                return Ok(Some(record));
            }
            self.extend_record(&mut record, remaining, maximum)?;
            self.page_index = self.page.len();
        }
    }

    pub(super) fn discarded_incomplete(&self) -> bool {
        self.discarded_incomplete
    }

    fn extend_record(
        &self,
        record: &mut Vec<u8>,
        bytes: &[u8],
        maximum: usize,
    ) -> BridgeResult<()> {
        let new_length = record
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| protocol_error("protocol record length overflowed"))?;
        if new_length > maximum {
            return Err(protocol_error("protocol record is oversized"));
        }
        record.extend_from_slice(bytes);
        Ok(())
    }

    pub(super) async fn read_to_end(mut self, maximum: usize) -> BridgeResult<Vec<u8>> {
        if self.length > maximum as u64 {
            return Err(protocol_error("fixed stream exceeded its protocol bound"));
        }
        let capacity = usize::try_from(self.length)
            .map_err(|_| protocol_error("fixed stream length is invalid"))?;
        let mut bytes = Vec::with_capacity(capacity);
        while self.offset < self.length || self.page_index < self.page.len() {
            if self.page_index == self.page.len() {
                let page = self
                    .output
                    .read(self.stream, self.offset, CURSOR_PAGE_BYTES)
                    .await?;
                self.offset = page.next_offset;
                self.page = page.bytes;
                self.page_index = 0;
                if self.page.is_empty() && !page.eof {
                    return Err(protocol_error("fixed stream cursor made no progress"));
                }
            }
            bytes.extend_from_slice(&self.page[self.page_index..]);
            self.page_index = self.page.len();
        }
        if bytes.len() != capacity {
            return Err(protocol_error("fixed stream length changed while parsing"));
        }
        Ok(bytes)
    }
}

pub(super) async fn read_small_stream(
    output: &InternalCapturedOutput,
    stream: StreamKind,
    maximum: usize,
) -> BridgeResult<Vec<u8>> {
    SpoolCursor::new(output, stream, maximum)?
        .read_to_end(maximum)
        .await
}

pub(super) async fn capability_mismatch(
    result: &FixedRunResult,
    required: &'static [&'static str],
) -> BridgeResult<Option<String>> {
    let output = &result.output;
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
        return Err(protocol_error("capability mismatch record is malformed"));
    }
    let rest = &page.bytes[PREFIX.len()..];
    let Some(value) = rest
        .strip_prefix(b"CAPABILITY=")
        .and_then(|value| value.strip_suffix(&[0]))
    else {
        return Err(protocol_error("capability mismatch record is malformed"));
    };
    if value.is_empty() || value.contains(&0) {
        return Err(protocol_error("capability mismatch record is malformed"));
    }
    let key = std::str::from_utf8(value)
        .map_err(|_| protocol_error("capability mismatch key is invalid"))?;
    if !required.contains(&key) {
        return Err(protocol_error(
            "capability mismatch named an unexpected key",
        ));
    }
    Ok(Some(key.to_owned()))
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
    fn task78_owned_utf8_encoding_reuses_the_input_allocation() {
        let bytes = b"owned preview".to_vec();
        let pointer = bytes.as_ptr();
        let encoded = encode_owned_bytes(bytes);
        assert_eq!(encoded.encoding, ValueEncoding::Utf8);
        assert_eq!(encoded.value, "owned preview");
        assert_eq!(encoded.value.as_ptr(), pointer);
    }

    #[tokio::test]
    async fn spool_cursor_nul_field_crosses_the_sixty_four_kib_page_boundary() {
        let directory = tempfile::TempDir::new().unwrap();
        let mut bytes = vec![b'a'; 64 * 1024];
        bytes.push(0);
        bytes.extend_from_slice(b"tail\0");
        let output = InternalCapturedOutput::for_test(directory.path(), &bytes, b"");
        let mut cursor = SpoolCursor::new(&output, StreamKind::Stdout, bytes.len()).unwrap();
        assert_eq!(
            cursor.next_field(64 * 1024).await.unwrap().unwrap().len(),
            64 * 1024
        );
        assert_eq!(cursor.next_field(16).await.unwrap().unwrap(), b"tail");
        assert!(cursor.next_field(16).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn spool_cursor_json_line_crosses_the_sixty_four_kib_page_boundary() {
        let directory = tempfile::TempDir::new().unwrap();
        let mut bytes = vec![b' '; 64 * 1024 - 1];
        bytes.extend_from_slice(b"{}\nnext\n");
        let output = InternalCapturedOutput::for_test(directory.path(), &bytes, b"");
        let mut cursor = SpoolCursor::new(&output, StreamKind::Stdout, bytes.len()).unwrap();
        let first = cursor.next_line(64 * 1024 + 1).await.unwrap().unwrap();
        assert_eq!(&first[first.len() - 2..], b"{}");
        assert_eq!(cursor.next_line(16).await.unwrap().unwrap(), b"next");
        assert!(cursor.next_line(16).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn exact_eight_mib_plus_one_capped_cursor_keeps_only_complete_groups() {
        let mut bytes = Vec::with_capacity(crate::MAX_FRAME_BYTES + 1);
        while bytes.len() + 10 <= crate::MAX_FRAME_BYTES {
            bytes.extend_from_slice(b"a\0b\0c\0d\0e\0");
        }
        bytes.resize(crate::MAX_FRAME_BYTES + 1, b'x');
        let directory = tempfile::TempDir::new().unwrap();
        let output = InternalCapturedOutput::for_test(directory.path(), &bytes, b"");
        let mut cursor =
            SpoolCursor::new(&output, StreamKind::Stdout, crate::MAX_FRAME_BYTES + 1).unwrap();
        let mut fields = 0usize;
        while cursor
            .next_field_capped(crate::MAX_FRAME_BYTES)
            .await
            .unwrap()
            .is_some()
        {
            fields += 1;
        }
        assert!(fields > 0);
        assert_eq!(fields % 5, 0);
    }
}
