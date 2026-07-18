// The wire-facing error schema intentionally stores six optional strings inline,
// and BridgeResult's exact public shape is Result<T, BridgeError>.
#![allow(clippy::result_large_err)]

pub mod config;
pub mod error;
pub mod path;
pub mod quote;

pub use error::{BridgeError, BridgeResult, ErrorCode, ErrorDetails};

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_READ_BYTES: usize = 1024 * 1024;
pub const MAX_WRITE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
