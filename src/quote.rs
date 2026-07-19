#![allow(
    clippy::result_large_err,
    reason = "Task 1 requires quoting functions to return the exact BridgeResult shape"
)]

use crate::error::{BridgeError, BridgeResult};

pub fn shell_word(value: &str) -> BridgeResult<String> {
    let word = PreparedShellWord::new(value)?;
    let mut encoded = String::with_capacity(word.len());
    word.push_to(&mut encoded)?;
    Ok(encoded)
}

pub(crate) struct PreparedShellWord<'a> {
    value: &'a str,
    length: usize,
}

pub(crate) struct PreparedShellWordParts<'a, const N: usize> {
    values: [&'a str; N],
    length: usize,
}

impl<'a> PreparedShellWord<'a> {
    pub(crate) fn new(value: &'a str) -> BridgeResult<Self> {
        Ok(Self {
            value,
            length: checked_shell_word_len(value)?,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.length
    }

    pub(crate) fn push_to(&self, encoded: &mut String) -> BridgeResult<()> {
        if encoded.capacity().saturating_sub(encoded.len()) < self.length {
            return Err(quote_too_large());
        }
        push_prevalidated_shell_word(encoded, self.value);
        Ok(())
    }
}

impl<'a, const N: usize> PreparedShellWordParts<'a, N> {
    pub(crate) fn new(values: [&'a str; N]) -> BridgeResult<Self> {
        let (value_length, quote_count) =
            values
                .iter()
                .try_fold((0usize, 0usize), |(value_length, quote_count), value| {
                    let (next_length, next_quotes) = checked_shell_value_stats(value)?;
                    Ok::<_, BridgeError>((
                        value_length
                            .checked_add(next_length)
                            .ok_or_else(quote_too_large)?,
                        quote_count
                            .checked_add(next_quotes)
                            .ok_or_else(quote_too_large)?,
                    ))
                })?;
        let length = checked_shell_word_len_from_stats(value_length, quote_count)?;
        Ok(Self { values, length })
    }

    pub(crate) fn len(&self) -> usize {
        self.length
    }

    pub(crate) fn push_to(&self, encoded: &mut String) -> BridgeResult<()> {
        if encoded.capacity().saturating_sub(encoded.len()) < self.length {
            return Err(quote_too_large());
        }
        encoded.push('\'');
        for value in self.values {
            push_prevalidated_shell_value(encoded, value);
        }
        encoded.push('\'');
        Ok(())
    }
}

fn checked_shell_word_len(value: &str) -> BridgeResult<usize> {
    let (value_length, quote_count) = checked_shell_value_stats(value)?;
    checked_shell_word_len_from_stats(value_length, quote_count)
}

fn checked_shell_value_stats(value: &str) -> BridgeResult<(usize, usize)> {
    if value.as_bytes().contains(&0) {
        return Err(BridgeError::invalid_argument(
            "NUL is not representable in a shell word",
        ));
    }
    Ok((
        value.len(),
        value.bytes().filter(|byte| *byte == b'\'').count(),
    ))
}

fn checked_shell_word_len_from_stats(
    value_length: usize,
    quote_count: usize,
) -> BridgeResult<usize> {
    value_length
        .checked_add(2)
        .and_then(|length| quote_count.checked_mul(4)?.checked_add(length))
        .ok_or_else(quote_too_large)
}

fn push_prevalidated_shell_word(encoded: &mut String, value: &str) {
    encoded.push('\'');
    push_prevalidated_shell_value(encoded, value);
    encoded.push('\'');
}

fn push_prevalidated_shell_value(encoded: &mut String, value: &str) {
    let mut remaining = value;
    while let Some(index) = remaining.find('\'') {
        encoded.push_str(&remaining[..index]);
        encoded.push_str("'\"'\"'");
        remaining = &remaining[index + 1..];
    }
    encoded.push_str(remaining);
}

fn quote_too_large() -> BridgeError {
    BridgeError::new(
        crate::error::ErrorCode::RequestTooLarge,
        "shell word is too large",
        false,
    )
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

#[cfg(test)]
mod tests {
    use super::{PreparedShellWord, PreparedShellWordParts, shell_word};

    #[test]
    fn task78_shell_word_exact_length_and_bounded_append_match_the_public_encoder() {
        for value in ["", "plain", "quote'quote", "line\n$()`*", "é'中"] {
            let expected = shell_word(value).unwrap();
            let word = PreparedShellWord::new(value).unwrap();
            assert_eq!(word.len(), expected.len());
            let mut rendered = String::with_capacity(expected.len());
            word.push_to(&mut rendered).unwrap();
            assert_eq!(rendered, expected);
            assert!(rendered.capacity() >= expected.len());

            if !expected.is_empty() {
                let mut undersized = String::with_capacity(expected.len() - 1);
                let error = word.push_to(&mut undersized).unwrap_err();
                assert_eq!(error.code, crate::error::ErrorCode::RequestTooLarge);
                assert!(undersized.is_empty());
            }
        }
        assert!(PreparedShellWord::new("bad\0word").is_err());
    }

    #[test]
    fn segmented_shell_word_matches_quoting_the_concatenated_value() {
        let expected = shell_word("prefix'payload\nsuffix").unwrap();
        let word = PreparedShellWordParts::new(["prefix'", "payload\n", "suffix"]).unwrap();
        assert_eq!(word.len(), expected.len());
        let mut rendered = String::with_capacity(word.len());
        word.push_to(&mut rendered).unwrap();
        assert_eq!(rendered, expected);
    }
}
