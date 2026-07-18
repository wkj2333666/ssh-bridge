pub mod capability;
pub mod config;
pub mod error;
pub mod path;
pub mod quote;
pub mod ssh;

pub use error::{BridgeError, BridgeResult, ErrorCode, ErrorDetails};

pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_READ_BYTES: usize = 1024 * 1024;
pub const MAX_WRITE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
