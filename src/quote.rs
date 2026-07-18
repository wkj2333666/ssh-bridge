use crate::error::{BridgeError, BridgeResult};

pub fn shell_word(value: &str) -> BridgeResult<String> {
    if value.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "NUL is not representable in a shell word",
        ));
    }
    Ok(format!("'{}'", value.replace('\'', "'\"'\"'")))
}

pub fn fixed_command(script: &str, args: &[&str]) -> BridgeResult<String> {
    if script.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "NUL is not representable in a shell command",
        ));
    }

    let mut command = script.to_owned();
    for argument in args {
        command.push(' ');
        command.push_str(&shell_word(argument)?);
    }
    Ok(command)
}
