use std::error::Error;
use std::fmt;
use std::io::{self, Write};

use serde::Serialize;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use super::{RequestId, ToolDefinition, WireBudget};
use crate::capability::MAX_SHELL_VERSION_BYTES;
use crate::config::MAX_REMOTE_CONTEXT_ROOT_BYTES;

pub const MAX_CONTEXT_ROOT_WIRE_EXPANSION: usize = 13;
pub const MAX_REQUEST_ID_WIRE_BYTES: usize = super::MAX_REQUEST_ID_WIRE_BYTES;
pub const MIN_FIXED_RESPONSE_RESERVE: usize = 64 * 1024;
pub const MIN_MCP_FRAME_BYTES: usize = 1024 * 1024;

const _: () =
    assert!(MAX_REMOTE_CONTEXT_ROOT_BYTES <= usize::MAX / MAX_CONTEXT_ROOT_WIRE_EXPANSION);
const _: () = assert!(
    MIN_MCP_FRAME_BYTES
        >= MAX_REMOTE_CONTEXT_ROOT_BYTES * MAX_CONTEXT_ROOT_WIRE_EXPANSION
            + MAX_REQUEST_ID_WIRE_BYTES
            + MIN_FIXED_RESPONSE_RESERVE
);
const _: () = assert!(MAX_SHELL_VERSION_BYTES <= MIN_FIXED_RESPONSE_RESERVE);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameEvent {
    Frame(Vec<u8>),
    Oversized,
    PartialEof,
    Eof,
}

pub struct FrameReader<R> {
    reader: R,
    limit: usize,
    retained: Vec<u8>,
    discarding: bool,
}

impl<R: AsyncBufRead + Unpin> FrameReader<R> {
    pub fn new(reader: R, limit: usize) -> Self {
        Self {
            reader,
            limit,
            retained: Vec::new(),
            discarding: false,
        }
    }

    pub async fn next_frame(&mut self) -> io::Result<FrameEvent> {
        loop {
            let available = self.reader.fill_buf().await?;
            if available.is_empty() {
                let partial = self.discarding || !self.retained.is_empty();
                self.discarding = false;
                self.retained.clear();
                return Ok(if partial {
                    FrameEvent::PartialEof
                } else {
                    FrameEvent::Eof
                });
            }

            let newline = available.iter().position(|byte| *byte == b'\n');
            let inspected = newline.map_or(available.len(), |position| position + 1);

            if self.discarding {
                self.reader.consume(inspected);
                if newline.is_some() {
                    self.discarding = false;
                    self.retained.clear();
                    return Ok(FrameEvent::Oversized);
                }
                continue;
            }

            let payload_len = newline.unwrap_or(available.len());
            let remaining = self.limit.saturating_sub(self.retained.len());
            if payload_len <= remaining {
                if payload_len != 0 {
                    self.retained.reserve_exact(payload_len);
                    self.retained.extend_from_slice(&available[..payload_len]);
                }
                self.reader.consume(inspected);
                if newline.is_some() {
                    return Ok(FrameEvent::Frame(std::mem::take(&mut self.retained)));
                }
                continue;
            }

            if remaining != 0 {
                self.retained.reserve_exact(remaining);
                self.retained.extend_from_slice(&available[..remaining]);
            }
            self.reader.consume(inspected);
            self.retained.clear();
            if newline.is_some() {
                return Ok(FrameEvent::Oversized);
            }
            self.discarding = true;
        }
    }
}

#[derive(Debug)]
pub struct CappedJsonBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl CappedJsonBuffer {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for CappedJsonBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(buffer.len()) else {
            return Err(capacity_error());
        };
        if next_len > self.limit {
            return Err(capacity_error());
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capacity_error() -> io::Error {
    io::Error::other("compact JSON frame exceeds configured bound")
}

pub fn serialize_json_line<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<Vec<u8>, SerializeLineError> {
    let mut output = CappedJsonBuffer::new(limit);
    serde_json::to_writer(&mut output, value).map_err(|error| {
        if error.io_error_kind() == Some(io::ErrorKind::Other) {
            SerializeLineError::CapacityExceeded
        } else {
            SerializeLineError::Serialization
        }
    })?;
    let mut bytes = output.into_inner();
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeLineError {
    CapacityExceeded,
    Serialization,
}

impl fmt::Display for SerializeLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded => {
                formatter.write_str("compact JSON frame exceeds configured bound")
            }
            Self::Serialization => formatter.write_str("failed to serialize compact JSON frame"),
        }
    }
}

impl Error for SerializeLineError {}

#[derive(Debug)]
pub enum WriteJsonLineError {
    Serialize(SerializeLineError),
    Io(io::Error),
}

impl fmt::Display for WriteJsonLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(_) => formatter.write_str("failed to serialize bounded JSON line"),
            Self::Io(_) => formatter.write_str("failed to write JSON line"),
        }
    }
}

impl Error for WriteJsonLineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialize(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}

pub async fn write_json_line<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
    limit: usize,
) -> Result<(), WriteJsonLineError> {
    let line = serialize_json_line(value, limit).map_err(WriteJsonLineError::Serialize)?;
    writer
        .write_all(&line)
        .await
        .map_err(WriteJsonLineError::Io)
}

#[derive(Serialize)]
struct ToolsListResult<'a> {
    tools: &'a [ToolDefinition],
}

#[derive(Serialize)]
struct ToolsListResponse<'a> {
    jsonrpc: &'static str,
    id: &'a RequestId,
    result: ToolsListResult<'a>,
}

pub fn exact_tools_list_response_bytes(
    definitions: &[ToolDefinition],
    id: &RequestId,
) -> Result<usize, serde_json::Error> {
    count_json_bytes(&ToolsListResponse {
        jsonrpc: "2.0",
        id,
        result: ToolsListResult { tools: definitions },
    })
}

pub fn required_mcp_frame_bytes(
    definitions: &[ToolDefinition],
    compact_fallback_bytes: usize,
    id: &RequestId,
) -> Result<usize, serde_json::Error> {
    let fallback_response_bytes = response_envelope_bytes(id)?
        .checked_add(compact_fallback_bytes)
        .ok_or_else(frame_size_error)?;
    Ok(MIN_MCP_FRAME_BYTES
        .max(fallback_response_bytes)
        .max(exact_tools_list_response_bytes(definitions, id)?))
}

#[derive(Default)]
struct CountingWriter {
    bytes: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(capacity_error)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn count_json_bytes<T: Serialize>(value: &T) -> Result<usize, serde_json::Error> {
    let mut counter = CountingWriter::default();
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.bytes)
}

#[derive(Serialize)]
struct ResultEnvelope<'a, T> {
    jsonrpc: &'static str,
    id: &'a RequestId,
    result: T,
}

fn response_envelope_bytes(id: &RequestId) -> Result<usize, serde_json::Error> {
    if count_json_bytes(id)? > MAX_REQUEST_ID_WIRE_BYTES {
        return Err(frame_size_error());
    }
    count_json_bytes(&ResultEnvelope {
        jsonrpc: "2.0",
        id,
        result: (),
    })?
    .checked_sub(b"null".len())
    .ok_or_else(frame_size_error)
}

fn frame_size_error() -> serde_json::Error {
    serde_json::Error::io(io::Error::other("invalid compact JSON frame size"))
}

impl WireBudget {
    pub fn for_response(
        max_frame_bytes: usize,
        id: &RequestId,
        compact_fallback_bytes: usize,
    ) -> Option<Self> {
        let envelope_bytes = response_envelope_bytes(id).ok()?;
        let reserved = envelope_bytes.checked_add(compact_fallback_bytes)?;
        Some(Self {
            result_bytes: max_frame_bytes.checked_sub(reserved)?,
            compact_fallback_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameEvent, FrameReader};

    #[tokio::test]
    async fn task7_frame_retention_never_exceeds_limit_without_a_delimiter() {
        let limit = 1024;
        let wire = vec![b'x'; 4 * 1024 * 1024];
        let mut reader = FrameReader::new(tokio::io::BufReader::new(wire.as_slice()), limit);

        assert_eq!(reader.next_frame().await.unwrap(), FrameEvent::PartialEof);
        assert!(reader.retained.capacity() <= limit);
    }
}
