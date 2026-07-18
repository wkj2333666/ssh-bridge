use std::fmt;

use serde::Serialize;

pub type BridgeResult<T> = Result<T, BridgeError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    HostKeyUnknown,
    AuthRequired,
    ConnectTimeout,
    RemoteCapabilityMissing,
    PathOutsideRoot,
    ReadOnlyHost,
    WriteConflict,
    OutputLimit,
    RequestTooLarge,
    ProtocolError,
    Cancelled,
    RemoteExit,
    InvalidConfig,
    InvalidArgument,
    Io,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ErrorDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BridgeError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub details: ErrorDetails,
}

impl BridgeError {
    pub fn new(code: ErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            retryable,
            details: ErrorDetails::default(),
        }
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidArgument, message, false)
    }

    pub fn invalid_config(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidConfig, message, false)
    }

    pub fn io(error: impl fmt::Display) -> Self {
        Self::new(ErrorCode::Io, error.to_string(), false)
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for BridgeError {}

impl From<std::io::Error> for BridgeError {
    fn from(error: std::io::Error) -> Self {
        Self::io(error)
    }
}
