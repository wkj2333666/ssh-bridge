use crate::error::BridgeResult;
use crate::quote::shell_word;

#[allow(dead_code)]
pub(crate) const DISPATCHER_PROTOCOL_VERSION: &str = "codex-ssh-dispatcher/1";
pub(crate) const DISPATCHER_SCRIPT: &str = include_str!("dispatcher.sh");

pub(crate) fn dispatcher_command(max_frame_bytes: usize) -> BridgeResult<String> {
    if max_frame_bytes == 0 {
        return Err(crate::error::BridgeError::invalid_argument(
            "SSH dispatcher frame limit must be positive",
        ));
    }
    let script = shell_word(DISPATCHER_SCRIPT)?;
    let tag = shell_word("codex-ssh-dispatcher-1")?;
    let max_frame = shell_word(&max_frame_bytes.to_string())?;
    Ok(format!("sh -c {script} -- {tag} {max_frame}"))
}

#[cfg(test)]
mod tests {
    use super::{DISPATCHER_PROTOCOL_VERSION, DISPATCHER_SCRIPT, dispatcher_command};

    #[test]
    fn dispatcher_command_is_a_single_quoted_posix_shell_program() {
        let command = dispatcher_command(4096).unwrap();
        assert!(command.starts_with("sh -c "));
        assert!(command.contains("codex-ssh-dispatcher-1"));
        assert!(!command.as_bytes().contains(&0));
    }

    #[test]
    fn dispatcher_protocol_and_script_are_bounded_constants() {
        assert_eq!(DISPATCHER_PROTOCOL_VERSION, "codex-ssh-dispatcher/1");
        assert!(DISPATCHER_SCRIPT.len() < 64 * 1024);
        assert!(!DISPATCHER_SCRIPT.as_bytes().contains(&0));
    }
}
