use std::collections::BTreeSet;

use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult, ErrorCode};

use super::{ApplyPatchRequest, ApplyPatchResult, RemoteBridge};

const MAX_PATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_PATCH_FILES: usize = 32;
const MAX_PATCH_HUNKS: usize = 4_096;
const MAX_PATCH_BODY_LINES: usize = 100_000;
const MAX_PATCH_PATH_BYTES: usize = 64 * 1024;
const NO_NEWLINE_MARKER: &str = "\\ No newline at end of file";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilePatch {
    pub path: String,
    pub operation: FilePatchOperation,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilePatchOperation {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hunk {
    pub old: HunkRange,
    pub new: HunkRange,
    pub lines: Vec<HunkLine>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HunkRange {
    pub start: usize,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HunkLine {
    pub kind: HunkLineKind,
    pub text: String,
    pub has_lf: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HunkLineKind {
    Context,
    Remove,
    Add,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HeaderPath {
    Null,
    Relative(String),
}

#[derive(Debug, Clone, Copy)]
struct RecordCursor<'a> {
    remainder: &'a str,
    finished: bool,
}

impl<'a> RecordCursor<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            remainder: input,
            finished: input.is_empty(),
        }
    }

    fn peek(&self) -> Option<&'a str> {
        if self.finished {
            return None;
        }
        Some(match self.remainder.find('\n') {
            Some(end) => &self.remainder[..end],
            None => self.remainder,
        })
    }

    fn next(&mut self) -> Option<&'a str> {
        if self.finished {
            return None;
        }
        match self.remainder.find('\n') {
            Some(end) => {
                let record = &self.remainder[..end];
                self.remainder = &self.remainder[end + 1..];
                self.finished = self.remainder.is_empty();
                Some(record)
            }
            None => {
                self.finished = true;
                Some(self.remainder)
            }
        }
    }
}

pub(crate) fn parse_patch(input: &str) -> BridgeResult<Vec<FilePatch>> {
    if input.len() > MAX_PATCH_BYTES {
        return Err(patch_too_large("patch exceeds the compiled byte limit"));
    }
    if input.as_bytes().contains(&0) {
        return Err(invalid_patch("patch contains NUL"));
    }

    let mut records = RecordCursor::new(input);
    if records.peek().is_none() {
        return Err(invalid_patch("patch is empty"));
    }

    let mut patches = Vec::new();
    let mut paths = BTreeSet::new();
    let mut total_hunks = 0usize;
    let mut total_body_lines = 0usize;

    while records.peek().is_some() {
        if patches.len() == MAX_PATCH_FILES {
            return Err(patch_too_large("patch contains too many files"));
        }
        let old = parse_header_path(
            records
                .next()
                .ok_or_else(|| invalid_patch("patch old-file header is missing"))?,
            "--- ",
            "a/",
            "patch old-file header is invalid",
        )?;
        let new_record = records
            .next()
            .ok_or_else(|| invalid_patch("patch new-file header is missing"))?;
        let new = parse_header_path(new_record, "+++ ", "b/", "patch new-file header is invalid")?;

        let (path, operation) = classify_headers(old, new)?;
        if !paths.insert(path.clone()) {
            return Err(invalid_patch("patch contains a duplicate path"));
        }

        let mut hunks = Vec::new();
        let mut changed = false;
        while records
            .peek()
            .is_some_and(|record| record.starts_with("@@ -"))
        {
            total_hunks = total_hunks
                .checked_add(1)
                .ok_or_else(|| patch_too_large("patch hunk count overflowed"))?;
            if total_hunks > MAX_PATCH_HUNKS {
                return Err(patch_too_large("patch contains too many hunks"));
            }

            let header = records
                .next()
                .ok_or_else(|| invalid_patch("patch hunk header is missing"))?;
            let (old, new) = parse_hunk_header(header)?;
            let mut lines = Vec::new();
            let mut old_used = 0usize;
            let mut new_used = 0usize;

            while old_used < old.count || new_used < new.count {
                let record = records
                    .peek()
                    .ok_or_else(|| invalid_patch("patch hunk body is incomplete"))?;
                if record == NO_NEWLINE_MARKER {
                    mark_previous_no_newline(&mut lines)?;
                    records.next();
                    continue;
                }

                let (kind, text) = parse_body_record(record)?;
                match kind {
                    HunkLineKind::Context => {
                        old_used = increment_hunk_count(old_used, old.count)?;
                        new_used = increment_hunk_count(new_used, new.count)?;
                    }
                    HunkLineKind::Remove => {
                        old_used = increment_hunk_count(old_used, old.count)?;
                        changed = true;
                    }
                    HunkLineKind::Add => {
                        new_used = increment_hunk_count(new_used, new.count)?;
                        changed = true;
                    }
                }
                total_body_lines = total_body_lines
                    .checked_add(1)
                    .ok_or_else(|| patch_too_large("patch body count overflowed"))?;
                if total_body_lines > MAX_PATCH_BODY_LINES {
                    return Err(patch_too_large("patch contains too many body lines"));
                }
                lines.push(HunkLine {
                    kind,
                    text: text.to_owned(),
                    has_lf: true,
                });
                records.next();
            }
            if records.peek() == Some(NO_NEWLINE_MARKER) {
                mark_previous_no_newline(&mut lines)?;
                records.next();
            }
            if old_used != old.count || new_used != new.count {
                return Err(invalid_patch("patch hunk body count is invalid"));
            }
            hunks.push(Hunk { old, new, lines });
        }

        if hunks.is_empty() {
            return Err(invalid_patch("patch file has no hunks"));
        }
        if !changed {
            return Err(invalid_patch("patch file has no changes"));
        }
        validate_operation_hunks(operation, &hunks)?;
        validate_no_newline_positions(&hunks)?;
        if records
            .peek()
            .is_some_and(|record| !record.starts_with("--- "))
        {
            return Err(invalid_patch("patch contains an unexpected record"));
        }
        patches.push(FilePatch {
            path,
            operation,
            hunks,
        });
    }

    Ok(patches)
}

fn parse_header_path(
    record: &str,
    header_prefix: &str,
    path_prefix: &str,
    message: &'static str,
) -> BridgeResult<HeaderPath> {
    let value = record
        .strip_prefix(header_prefix)
        .ok_or_else(|| invalid_patch(message))?;
    if value.contains(['\0', '\t', '\r', '\n']) {
        return Err(invalid_patch(message));
    }
    if value == "/dev/null" {
        return Ok(HeaderPath::Null);
    }
    let relative = value
        .strip_prefix(path_prefix)
        .ok_or_else(|| invalid_patch(message))?;
    validate_patch_path(relative)?;
    Ok(HeaderPath::Relative(relative.to_owned()))
}

fn validate_patch_path(path: &str) -> BridgeResult<()> {
    if path.len() > MAX_PATCH_PATH_BYTES {
        return Err(patch_too_large(
            "patch path exceeds the compiled byte limit",
        ));
    }
    if path.is_empty() || path.starts_with('/') {
        return Err(invalid_patch("patch path is not canonical"));
    }
    for component in path.split('/') {
        if component == ".." {
            return Err(BridgeError::new(
                ErrorCode::PathOutsideRoot,
                "patch path contains traversal",
                false,
            ));
        }
        if component.is_empty() || component == "." {
            return Err(invalid_patch("patch path is not canonical"));
        }
    }
    Ok(())
}

fn classify_headers(
    old: HeaderPath,
    new: HeaderPath,
) -> BridgeResult<(String, FilePatchOperation)> {
    match (old, new) {
        (HeaderPath::Relative(old), HeaderPath::Relative(new)) if old == new => {
            Ok((old, FilePatchOperation::Update))
        }
        (HeaderPath::Null, HeaderPath::Relative(new)) => Ok((new, FilePatchOperation::Create)),
        (HeaderPath::Relative(old), HeaderPath::Null) => Ok((old, FilePatchOperation::Delete)),
        _ => Err(invalid_patch(
            "patch file headers do not name one operation",
        )),
    }
}

fn parse_hunk_header(record: &str) -> BridgeResult<(HunkRange, HunkRange)> {
    if record.contains(['\0', '\r', '\n']) {
        return Err(invalid_patch("patch hunk header is invalid"));
    }
    let rest = record
        .strip_prefix("@@ -")
        .ok_or_else(|| invalid_patch("patch hunk header is invalid"))?;
    let (old, rest) = rest
        .split_once(" +")
        .ok_or_else(|| invalid_patch("patch hunk header is invalid"))?;
    let (new, suffix) = rest
        .split_once(" @@")
        .ok_or_else(|| invalid_patch("patch hunk header is invalid"))?;
    if !suffix.is_empty()
        && suffix
            .strip_prefix(' ')
            .is_none_or(|section| section.is_empty())
    {
        return Err(invalid_patch("patch hunk header is invalid"));
    }
    Ok((parse_range(old)?, parse_range(new)?))
}

fn parse_range(value: &str) -> BridgeResult<HunkRange> {
    let mut fields = value.split(',');
    let start = parse_usize(fields.next().unwrap_or_default())?;
    let count = match fields.next() {
        Some(count) => parse_usize(count)?,
        None => 1,
    };
    if fields.next().is_some() || (count > 0 && start == 0) {
        return Err(invalid_patch("patch hunk range is invalid"));
    }
    if count > 0 {
        start
            .checked_sub(1)
            .and_then(|zero_based| zero_based.checked_add(count))
            .ok_or_else(|| invalid_patch("patch hunk range end overflowed"))?;
    }
    Ok(HunkRange { start, count })
}

fn parse_usize(value: &str) -> BridgeResult<usize> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_patch("patch hunk number is invalid"));
    }
    value
        .parse::<usize>()
        .map_err(|_| invalid_patch("patch hunk number is invalid"))
}

fn parse_body_record(record: &str) -> BridgeResult<(HunkLineKind, &str)> {
    let (prefix, text) = record
        .split_at_checked(1)
        .ok_or_else(|| invalid_patch("patch hunk body record is invalid"))?;
    let kind = match prefix.as_bytes()[0] {
        b' ' => HunkLineKind::Context,
        b'-' => HunkLineKind::Remove,
        b'+' => HunkLineKind::Add,
        _ => return Err(invalid_patch("patch hunk body record is invalid")),
    };
    Ok((kind, text))
}

fn increment_hunk_count(current: usize, maximum: usize) -> BridgeResult<usize> {
    let next = current
        .checked_add(1)
        .ok_or_else(|| invalid_patch("patch hunk body count overflowed"))?;
    if next > maximum {
        return Err(invalid_patch("patch hunk body count is invalid"));
    }
    Ok(next)
}

fn mark_previous_no_newline(lines: &mut [HunkLine]) -> BridgeResult<()> {
    let line = lines
        .last_mut()
        .ok_or_else(|| invalid_patch("patch no-newline marker is orphaned"))?;
    if !line.has_lf {
        return Err(invalid_patch("patch no-newline marker is duplicated"));
    }
    if line.text.is_empty() {
        return Err(invalid_patch(
            "patch no-newline marker cannot describe an empty record",
        ));
    }
    line.has_lf = false;
    Ok(())
}

fn validate_operation_hunks(operation: FilePatchOperation, hunks: &[Hunk]) -> BridgeResult<()> {
    match operation {
        FilePatchOperation::Create
            if hunks
                .iter()
                .any(|hunk| hunk.old != (HunkRange { start: 0, count: 0 })) =>
        {
            Err(invalid_patch("patch create has old-file content"))
        }
        FilePatchOperation::Delete if hunks.iter().any(|hunk| hunk.new.count != 0) => {
            Err(invalid_patch("patch delete has new-file content"))
        }
        _ => Ok(()),
    }
}

fn validate_no_newline_positions(hunks: &[Hunk]) -> BridgeResult<()> {
    let mut last_old = None;
    let mut last_new = None;
    for (hunk_index, hunk) in hunks.iter().enumerate() {
        for (line_index, line) in hunk.lines.iter().enumerate() {
            let position = (hunk_index, line_index);
            match line.kind {
                HunkLineKind::Context => {
                    last_old = Some(position);
                    last_new = Some(position);
                }
                HunkLineKind::Remove => last_old = Some(position),
                HunkLineKind::Add => last_new = Some(position),
            }
        }
    }
    for (hunk_index, hunk) in hunks.iter().enumerate() {
        for (line_index, line) in hunk.lines.iter().enumerate() {
            if line.has_lf {
                continue;
            }
            let position = Some((hunk_index, line_index));
            let valid = match line.kind {
                HunkLineKind::Context => position == last_old && position == last_new,
                HunkLineKind::Remove => position == last_old,
                HunkLineKind::Add => position == last_new,
            };
            if !valid {
                return Err(invalid_patch("patch no-newline marker is not final"));
            }
        }
    }
    Ok(())
}

fn invalid_patch(message: &'static str) -> BridgeError {
    BridgeError::invalid_argument(message)
}

fn patch_too_large(message: &'static str) -> BridgeError {
    BridgeError::new(ErrorCode::RequestTooLarge, message, false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PatchedFile {
    Write(Vec<u8>),
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogicalLine<'a> {
    text: &'a str,
    has_lf: bool,
}

#[derive(Debug, Clone, Copy)]
struct LogicalLineCursor<'a> {
    remainder: &'a str,
    consumed: usize,
}

impl<'a> LogicalLineCursor<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            remainder: input,
            consumed: 0,
        }
    }

    fn next(&mut self) -> BridgeResult<Option<LogicalLine<'a>>> {
        if self.remainder.is_empty() {
            return Ok(None);
        }
        let (text, has_lf, remainder) = match self.remainder.find('\n') {
            Some(end) => (&self.remainder[..end], true, &self.remainder[end + 1..]),
            None => (self.remainder, false, ""),
        };
        self.remainder = remainder;
        self.consumed = self
            .consumed
            .checked_add(1)
            .ok_or_else(|| invalid_patch("base logical-line count overflowed"))?;
        Ok(Some(LogicalLine { text, has_lf }))
    }
}

struct OutputBuilder {
    bytes: Vec<u8>,
    logical_lines: usize,
    can_append: bool,
    maximum_bytes: usize,
}

impl OutputBuilder {
    fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            logical_lines: 0,
            can_append: true,
            maximum_bytes,
        }
    }

    fn append(&mut self, line: LogicalLine<'_>) -> BridgeResult<()> {
        if !self.can_append {
            return Err(write_conflict("patch output follows a non-LF logical line"));
        }
        let added = line
            .text
            .len()
            .checked_add(usize::from(line.has_lf))
            .ok_or_else(|| patch_too_large("patched file size overflowed"))?;
        let new_len = self
            .bytes
            .len()
            .checked_add(added)
            .ok_or_else(|| patch_too_large("patched file size overflowed"))?;
        if new_len > self.maximum_bytes {
            return Err(patch_too_large(
                "patched file exceeds the compiled byte limit",
            ));
        }
        self.logical_lines = self
            .logical_lines
            .checked_add(1)
            .ok_or_else(|| patch_too_large("patched logical-line count overflowed"))?;
        self.bytes.extend_from_slice(line.text.as_bytes());
        if line.has_lf {
            self.bytes.push(b'\n');
        }
        self.can_append = line.has_lf;
        Ok(())
    }
}

pub(super) fn apply_file_patch(
    base: Option<(&[u8], &str)>,
    patch: &FilePatch,
    maximum_output_bytes: usize,
) -> BridgeResult<PatchedFile> {
    let base_bytes = match (patch.operation, base) {
        (FilePatchOperation::Create, None) => &[][..],
        (FilePatchOperation::Update | FilePatchOperation::Delete, Some((bytes, sha256))) => {
            let _expected_sha256 = sha256;
            bytes
        }
        _ => {
            return Err(write_conflict(
                "patch base presence does not match operation",
            ));
        }
    };
    let base_text =
        std::str::from_utf8(base_bytes).map_err(|_| invalid_patch("patch base is not UTF-8"))?;
    if base_bytes.contains(&0) {
        return Err(invalid_patch("patch base contains NUL"));
    }

    let mut base_lines = LogicalLineCursor::new(base_text);
    let mut output = OutputBuilder::new(maximum_output_bytes);
    let mut previous_zero_old_anchor = None;
    let mut previous_zero_new_anchor = None;

    for hunk in &patch.hunks {
        let old_anchor = range_anchor(hunk.old)?;
        let new_anchor = range_anchor(hunk.new)?;
        if hunk.old.count == 0 {
            if previous_zero_old_anchor == Some(old_anchor) {
                return Err(invalid_patch("patch repeats a zero-count old anchor"));
            }
            previous_zero_old_anchor = Some(old_anchor);
        }
        if hunk.new.count == 0 {
            if previous_zero_new_anchor == Some(new_anchor) {
                return Err(invalid_patch("patch repeats a zero-count new anchor"));
            }
            previous_zero_new_anchor = Some(new_anchor);
        }
        if old_anchor < base_lines.consumed {
            return Err(invalid_patch("patch hunks overlap or move backwards"));
        }
        while base_lines.consumed < old_anchor {
            let line = base_lines
                .next()?
                .ok_or_else(|| write_conflict("patch old position exceeds the base"))?;
            output.append(line)?;
        }
        if output.logical_lines != new_anchor {
            return Err(invalid_patch("patch new position is inconsistent"));
        }

        for line in &hunk.lines {
            match line.kind {
                HunkLineKind::Context | HunkLineKind::Remove => {
                    let base_line = base_lines
                        .next()?
                        .ok_or_else(|| write_conflict("patch expects missing base content"))?;
                    if base_line.text != line.text || base_line.has_lf != line.has_lf {
                        return Err(write_conflict("patch base content does not match"));
                    }
                    if line.kind == HunkLineKind::Context {
                        output.append(base_line)?;
                    }
                }
                HunkLineKind::Add => output.append(LogicalLine {
                    text: &line.text,
                    has_lf: line.has_lf,
                })?,
            }
        }
    }

    while let Some(line) = base_lines.next()? {
        output.append(line)?;
    }

    match patch.operation {
        FilePatchOperation::Create if output.bytes.is_empty() => {
            Err(invalid_patch("patch create produced an empty file"))
        }
        FilePatchOperation::Delete if !output.bytes.is_empty() => {
            Err(invalid_patch("patch delete produced file content"))
        }
        FilePatchOperation::Delete => Ok(PatchedFile::Delete),
        FilePatchOperation::Update if output.bytes.as_slice() == base_bytes => Err(write_conflict(
            "patch update would leave the file unchanged",
        )),
        FilePatchOperation::Create | FilePatchOperation::Update => {
            Ok(PatchedFile::Write(output.bytes))
        }
    }
}

fn range_anchor(range: HunkRange) -> BridgeResult<usize> {
    if range.count == 0 {
        Ok(range.start)
    } else {
        range
            .start
            .checked_sub(1)
            .ok_or_else(|| invalid_patch("patch hunk range is invalid"))
    }
}

fn write_conflict(message: &'static str) -> BridgeError {
    BridgeError::new(ErrorCode::WriteConflict, message, false)
}

pub(super) async fn apply_patch(
    _bridge: &RemoteBridge,
    request: ApplyPatchRequest,
    _cancel: CancellationToken,
) -> BridgeResult<ApplyPatchResult> {
    let patches = parse_patch(&request.patch)?;
    let _apply_file_patch = apply_file_patch;
    let mut error = BridgeError::invalid_argument("remote patch orchestration is not implemented");
    error.details.changed_paths = Some(Vec::new());
    error.details.not_changed_paths = Some(patches.into_iter().map(|patch| patch.path).collect());
    error.details.outcome_unknown_paths = Some(Vec::new());
    Err(error)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};

    use crate::ErrorCode;

    fn apply(base: Option<&[u8]>, patch: &str) -> crate::BridgeResult<super::PatchedFile> {
        let parsed = super::parse_patch(patch)?;
        assert_eq!(parsed.len(), 1);
        let sha256 = base.map(|bytes| format!("{:x}", Sha256::digest(bytes)));
        super::apply_file_patch(
            base.zip(sha256.as_deref()),
            &parsed[0],
            super::MAX_PATCH_BYTES,
        )
    }

    #[test]
    fn task6_parse_accepts_multiple_files_hunks_and_terminal_eof() {
        let patch = concat!(
            "--- a/a.txt\n",
            "+++ b/a.txt\n",
            "@@ -1,2 +1,2 @@ first\n",
            " one\n",
            "-two\n",
            "+TWO\n",
            "@@ -4 +4 @@\n",
            "-four\n",
            "+FOUR\n",
            "--- /dev/null\n",
            "+++ b/new.txt\n",
            "@@ -0,0 +1 @@\n",
            "+created",
        );
        let parsed = super::parse_patch(patch).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, "a.txt");
        assert_eq!(parsed[0].operation, super::FilePatchOperation::Update);
        assert_eq!(parsed[0].hunks.len(), 2);
        assert_eq!(parsed[1].path, "new.txt");
        assert_eq!(parsed[1].operation, super::FilePatchOperation::Create);
        assert_eq!(
            parsed[1].hunks[0].new,
            super::HunkRange { start: 1, count: 1 }
        );
        assert_eq!(parsed[1].hunks[0].lines[0].text, "created");
        assert!(parsed[1].hunks[0].lines[0].has_lf);
    }

    #[test]
    fn task6_parse_freezes_no_newline_marker_on_the_preceding_side() {
        let patch = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "-old\n\\ No newline at end of file\n",
            "+new\n\\ No newline at end of file\n",
        );
        let parsed = super::parse_patch(patch).unwrap();
        assert!(!parsed[0].hunks[0].lines[0].has_lf);
        assert!(!parsed[0].hunks[0].lines[1].has_lf);
    }

    #[test]
    fn task6_parse_rejects_every_non_language_form() {
        let cases = [
            ("", ErrorCode::InvalidArgument),
            (
                "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\tstamp\n+++ b/a\tstamp\n@@ -1 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\n+++ b/b\n@@ -1 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- /dev/null\n+++ /dev/null\n@@ -0,0 +1 @@\n+x\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/../a\n+++ b/../a\n@@ -1 +1 @@\n-a\n+b\n",
                ErrorCode::PathOutsideRoot,
            ),
            (
                "--- a/a//b\n+++ b/a//b\n@@ -1 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\n+++ b/a\n@@ -184467440737095516160 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\n+++ b/a\n@@ -1,2 +1 @@\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n\\ no newline at end of file\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- /dev/null\n+++ b/empty\n@@ -0,0 +0,0 @@\n",
                ErrorCode::InvalidArgument,
            ),
            ("GIT binary patch\n", ErrorCode::InvalidArgument),
            (
                "--- a/a\n+++ b/a\n@@ -1 +1 @@ trailing\r\n-a\n+b\n",
                ErrorCode::InvalidArgument,
            ),
            (
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\ntrailing prose\n",
                ErrorCode::InvalidArgument,
            ),
        ];
        for (input, code) in cases {
            assert_eq!(
                super::parse_patch(input).unwrap_err().code,
                code,
                "{input:?}"
            );
        }
    }

    #[test]
    fn task6_parse_rejects_duplicate_canonical_paths() {
        let patch = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n",
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-b\n+c\n",
        );
        assert_eq!(
            super::parse_patch(patch).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task6_parse_rejects_nonfinal_or_duplicate_no_newline_marker() {
        let cases = [
            concat!(
                "--- a/a\n+++ b/a\n@@ -1,2 +1 @@\n",
                "-one\n\\ No newline at end of file\n",
                "-two\n",
                "+new\n",
            ),
            concat!(
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
                "-old\n\\ No newline at end of file\n",
                "\\ No newline at end of file\n",
                "+new\n",
            ),
            concat!(
                "--- a/a\n+++ b/a\n@@ -1 +1,2 @@\n",
                " old\n\\ No newline at end of file\n",
                "+new\n",
            ),
            concat!(
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
                "-old\n",
                "+new\n\\ No newline at end of file\n",
                "@@ -2 +2 @@\n",
                "-later\n",
                "+LATER\n",
            ),
        ];
        for patch in cases {
            assert_eq!(
                super::parse_patch(patch).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "{patch:?}"
            );
        }
    }

    #[test]
    fn task6_parse_rejects_file_hunk_and_body_count_ceilings() {
        let mut files = String::new();
        for index in 0..=super::MAX_PATCH_FILES {
            write!(files, "--- /dev/null\n+++ b/f{index}\n@@ -0,0 +1 @@\n+x\n").unwrap();
        }
        assert_eq!(
            super::parse_patch(&files).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );

        let mut hunks = String::from("--- a/a\n+++ b/a\n");
        for index in 1..=super::MAX_PATCH_HUNKS + 1 {
            write!(hunks, "@@ -{index} +{index} @@\n-x\n+y\n").unwrap();
        }
        assert_eq!(
            super::parse_patch(&hunks).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );

        let mut lines = format!(
            "--- /dev/null\n+++ b/a\n@@ -0,0 +1,{} @@\n",
            super::MAX_PATCH_BODY_LINES + 1
        );
        for _ in 0..=super::MAX_PATCH_BODY_LINES {
            lines.push_str("+\n");
        }
        assert_eq!(
            super::parse_patch(&lines).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );
    }

    #[test]
    fn task6_parse_rejects_patch_and_path_byte_ceilings() {
        let oversized_patch = "x".repeat(super::MAX_PATCH_BYTES + 1);
        assert_eq!(
            super::parse_patch(&oversized_patch).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );

        let path = "p".repeat(super::MAX_PATCH_PATH_BYTES + 1);
        let patch = format!("--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n");
        assert_eq!(
            super::parse_patch(&patch).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );
    }

    #[test]
    fn task6_parse_accepts_every_exact_compiled_ceiling() {
        let mut files = String::new();
        for index in 0..super::MAX_PATCH_FILES {
            write!(files, "--- /dev/null\n+++ b/f{index}\n@@ -0,0 +1 @@\n+x\n").unwrap();
        }
        assert_eq!(
            super::parse_patch(&files).unwrap().len(),
            super::MAX_PATCH_FILES
        );

        let mut hunks = String::from("--- a/a\n+++ b/a\n");
        for index in 1..=super::MAX_PATCH_HUNKS {
            write!(hunks, "@@ -{index} +{index} @@\n-x\n+y\n").unwrap();
        }
        assert_eq!(
            super::parse_patch(&hunks).unwrap()[0].hunks.len(),
            super::MAX_PATCH_HUNKS
        );

        let mut body = format!(
            "--- /dev/null\n+++ b/body\n@@ -0,0 +1,{} @@\n",
            super::MAX_PATCH_BODY_LINES
        );
        for _ in 0..super::MAX_PATCH_BODY_LINES {
            body.push_str("+x\n");
        }
        assert_eq!(
            super::parse_patch(&body).unwrap()[0].hunks[0].lines.len(),
            super::MAX_PATCH_BODY_LINES
        );

        let path = "é".repeat(super::MAX_PATCH_PATH_BYTES / "é".len());
        assert_eq!(path.len(), super::MAX_PATCH_PATH_BYTES);
        let path_patch = format!("--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n");
        assert_eq!(super::parse_patch(&path_patch).unwrap()[0].path, path);

        let prefix = "--- /dev/null\n+++ b/exact\n@@ -0,0 +1 @@\n+";
        let exact_patch = format!(
            "{prefix}{}",
            "x".repeat(super::MAX_PATCH_BYTES - prefix.len())
        );
        assert_eq!(exact_patch.len(), super::MAX_PATCH_BYTES);
        super::parse_patch(&exact_patch).unwrap();
    }

    #[test]
    fn task6_parse_create_requires_exact_zero_old_range_shape() {
        let patch = concat!("--- /dev/null\n+++ b/a\n", "@@ -1,0 +1 @@\n", "+x\n",);
        assert_eq!(
            super::parse_patch(patch).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task6_parse_rejects_empty_non_lf_logical_records_of_every_kind() {
        let cases = [
            concat!(
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
                "-\n\\ No newline at end of file\n",
                "+x\n",
            ),
            concat!(
                "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
                "+\n\\ No newline at end of file\n",
                "-x\n",
            ),
            concat!(
                "--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n",
                "-old\n",
                "+new\n",
                " \n\\ No newline at end of file\n",
            ),
            concat!(
                "--- /dev/null\n+++ b/zero\n@@ -0,0 +1 @@\n",
                "+\n\\ No newline at end of file\n",
            ),
        ];
        for patch in cases {
            assert_eq!(
                super::parse_patch(patch).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "{patch:?}"
            );
        }
    }

    #[test]
    fn task6_parse_no_newline_finality_is_side_aware() {
        let remove_then_add = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "-old\n\\ No newline at end of file\n",
            "+new\n\\ No newline at end of file\n",
        );
        super::parse_patch(remove_then_add).unwrap();

        let add_then_remove = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "+new\n\\ No newline at end of file\n",
            "-old\n\\ No newline at end of file\n",
        );
        super::parse_patch(add_then_remove).unwrap();

        let context_finishes_both_sides = concat!(
            "--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n",
            "-old\n",
            "+new\n",
            " tail\n\\ No newline at end of file\n",
        );
        super::parse_patch(context_finishes_both_sides).unwrap();
    }

    #[test]
    fn task6_parse_freezes_crlf_eof_overflow_and_zero_anchor_boundaries() {
        let body_cr_is_literal = concat!("--- a/a\n+++ b/a\n@@ -1 +1 @@\n", "-old\r\n", "+new\r",);
        let parsed = super::parse_patch(body_cr_is_literal).unwrap();
        assert_eq!(parsed[0].hunks[0].lines[0].text, "old\r");
        assert_eq!(parsed[0].hunks[0].lines[1].text, "new\r");
        assert!(parsed[0].hunks[0].lines[1].has_lf);

        for patch in [
            "--- a/a\r\n+++ b/a\r\n@@ -1 +1 @@\r\n-a\r\n+b\r\n",
            "--- a/a\n+++ b/a\n@@ -0 +1 @@\n-a\n+b\n",
            "--- a/a\n+++ b/a\n@@ -1 +0 @@\n-a\n+b\n",
            "--- a/a\n+++ b/a\n@@ -1,184467440737095516160 +1 @@\n-a\n+b\n",
        ] {
            assert_eq!(
                super::parse_patch(patch).unwrap_err().code,
                ErrorCode::InvalidArgument,
                "{patch:?}"
            );
        }

        let exclusive_end_overflow =
            format!("--- a/a\n+++ b/a\n@@ -{},2 +1 @@\n-a\n-b\n+c\n", usize::MAX);
        assert_eq!(
            super::parse_patch(&exclusive_end_overflow)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );

        let zero_anchors = concat!(
            "--- a/a\n+++ b/a\n",
            "@@ -0,0 +1 @@\n+first\n",
            "@@ -1 +2,0 @@\n-first\n",
        );
        super::parse_patch(zero_anchors).unwrap();
    }

    #[test]
    fn task6_parser_record_cursor_has_constant_pointer_sized_state() {
        assert!(std::mem::size_of::<super::RecordCursor<'_>>() <= 3 * std::mem::size_of::<usize>());
    }

    #[test]
    fn task6_apply_preserves_untouched_terminal_lf_state() {
        let patch = concat!("--- a/a\n+++ b/a\n@@ -1 +1 @@\n", "-old\n+new\n",);
        assert_eq!(
            apply(Some(b"old\ntail"), patch).unwrap(),
            super::PatchedFile::Write(b"new\ntail".to_vec())
        );
        assert_eq!(
            apply(Some(b"old\ntail\n"), patch).unwrap(),
            super::PatchedFile::Write(b"new\ntail\n".to_vec())
        );
    }

    #[test]
    fn task6_apply_changes_terminal_lf_only_with_exact_markers() {
        let remove_lf = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "-old\n",
            "\\ No newline at end of file\n",
            "+new\n",
        );
        assert_eq!(
            apply(Some(b"old"), remove_lf).unwrap(),
            super::PatchedFile::Write(b"new\n".to_vec())
        );

        let add_no_lf = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "-old\n",
            "+new\n",
            "\\ No newline at end of file\n",
        );
        assert_eq!(
            apply(Some(b"old\n"), add_no_lf).unwrap(),
            super::PatchedFile::Write(b"new".to_vec())
        );
    }

    #[test]
    fn task6_apply_supports_create_empty_update_and_delete() {
        let create = concat!("--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n", "+made\n",);
        assert_eq!(
            apply(None, create).unwrap(),
            super::PatchedFile::Write(b"made\n".to_vec())
        );

        let empty = concat!("--- a/a\n+++ b/a\n@@ -1 +0,0 @@\n", "-old\n",);
        assert_eq!(
            apply(Some(b"old\n"), empty).unwrap(),
            super::PatchedFile::Write(Vec::new())
        );

        let delete = concat!("--- a/a\n+++ /dev/null\n@@ -1 +0,0 @@\n", "-old\n",);
        assert_eq!(
            apply(Some(b"old\n"), delete).unwrap(),
            super::PatchedFile::Delete
        );
    }

    #[test]
    fn task6_apply_validates_old_and_new_positions_not_only_counts() {
        let wrong_old = concat!("--- a/a\n+++ b/a\n@@ -2 +2 @@\n", "-one\n+ONE\n",);
        assert_eq!(
            apply(Some(b"one\ntwo\n"), wrong_old).unwrap_err().code,
            ErrorCode::WriteConflict
        );

        let wrong_new = concat!("--- a/a\n+++ b/a\n@@ -1 +2 @@\n", "-one\n+ONE\n",);
        assert_eq!(
            apply(Some(b"one\n"), wrong_new).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task6_apply_rejects_overlapping_and_repeated_zero_anchor_hunks() {
        let overlap = concat!(
            "--- a/a\n+++ b/a\n",
            "@@ -1 +1 @@\n-one\n+ONE\n",
            "@@ -1 +1 @@\n-one\n+again\n",
        );
        assert_eq!(
            apply(Some(b"one\n"), overlap).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let repeated_zero = concat!(
            "--- a/a\n+++ b/a\n",
            "@@ -0,0 +1 @@\n+first\n",
            "@@ -0,0 +2 @@\n+second\n",
        );
        assert_eq!(
            apply(Some(b"tail\n"), repeated_zero).unwrap_err().code,
            ErrorCode::InvalidArgument
        );

        let repeated_new_zero = concat!(
            "--- a/a\n+++ b/a\n",
            "@@ -1 +0,0 @@\n-a\n",
            "@@ -2 +0,0 @@\n-b\n",
        );
        assert_eq!(
            apply(Some(b"a\nb\n"), repeated_new_zero).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task6_apply_rejects_update_whose_complete_output_equals_base() {
        let patch = concat!("--- a/a\n+++ b/a\n@@ -1 +1 @@\n", "-old\n", "+old\n",);
        assert_eq!(
            apply(Some(b"old\n"), patch).unwrap_err().code,
            ErrorCode::WriteConflict
        );
    }

    #[test]
    fn task6_apply_matches_context_removal_and_lf_state_byte_for_byte() {
        for (base, patch) in [
            (&b"OLD\n"[..], "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n"),
            (&b"old"[..], "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n"),
            (
                &b"old\n"[..],
                concat!(
                    "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
                    "-old\n\\ No newline at end of file\n",
                    "+new\n",
                ),
            ),
        ] {
            assert_eq!(
                apply(Some(base), patch).unwrap_err().code,
                ErrorCode::WriteConflict
            );
        }

        let crlf = "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\r\n+new\r\n";
        assert_eq!(
            apply(Some(b"old\r\n"), crlf).unwrap(),
            super::PatchedFile::Write(b"new\r\n".to_vec())
        );
    }

    #[test]
    fn task6_apply_rejects_non_utf8_nul_and_wrong_base_presence() {
        let update = "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n";
        for base in [&b"\xff"[..], &b"old\0\n"[..]] {
            assert_eq!(
                apply(Some(base), update).unwrap_err().code,
                ErrorCode::InvalidArgument
            );
        }
        assert_eq!(
            apply(None, update).unwrap_err().code,
            ErrorCode::WriteConflict
        );

        let create = "--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+x\n";
        assert_eq!(
            apply(Some(b"exists\n"), create).unwrap_err().code,
            ErrorCode::WriteConflict
        );
    }

    #[test]
    fn task6_apply_rejects_delete_with_nonempty_output() {
        let patch = "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n";
        let mut parsed = super::parse_patch(patch).unwrap().remove(0);
        parsed.operation = super::FilePatchOperation::Delete;
        let sha256 = format!("{:x}", Sha256::digest(b"old\n"));
        assert_eq!(
            super::apply_file_patch(Some((b"old\n", &sha256)), &parsed, super::MAX_PATCH_BYTES,)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn task6_apply_rejects_per_file_output_overflow_before_allocation() {
        let patch = "--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+large\n";
        let parsed = super::parse_patch(patch).unwrap().remove(0);
        assert_eq!(
            super::apply_file_patch(None, &parsed, 5).unwrap_err().code,
            ErrorCode::RequestTooLarge
        );
    }

    #[test]
    fn task6_apply_non_lf_output_cannot_precede_untouched_or_added_suffix() {
        let untouched_suffix = concat!(
            "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
            "-old\n",
            "+new\n\\ No newline at end of file\n",
        );
        assert_eq!(
            apply(Some(b"old\ntail\n"), untouched_suffix)
                .unwrap_err()
                .code,
            ErrorCode::WriteConflict
        );

        let added_suffix = concat!(
            "--- a/a\n+++ b/a\n",
            "@@ -1 +1 @@\n-old\n+new\n",
            "@@ -2 +2 @@\n-tail\n+TAIL\n",
        );
        let mut parsed = super::parse_patch(added_suffix).unwrap().remove(0);
        parsed.hunks[0].lines[1].has_lf = false;
        let sha256 = format!("{:x}", Sha256::digest(b"old\ntail\n"));
        assert_eq!(
            super::apply_file_patch(
                Some((b"old\ntail\n", &sha256)),
                &parsed,
                super::MAX_PATCH_BYTES,
            )
            .unwrap_err()
            .code,
            ErrorCode::WriteConflict
        );
    }

    #[test]
    fn task6_apply_accepts_valid_zero_anchors_at_file_boundaries() {
        let insert_first = concat!("--- a/a\n+++ b/a\n@@ -0,0 +1 @@\n", "+head\n",);
        assert_eq!(
            apply(Some(b"tail\n"), insert_first).unwrap(),
            super::PatchedFile::Write(b"head\ntail\n".to_vec())
        );

        let insert_last = concat!("--- a/a\n+++ b/a\n@@ -1,0 +2 @@\n", "+tail\n",);
        assert_eq!(
            apply(Some(b"head\n"), insert_last).unwrap(),
            super::PatchedFile::Write(b"head\ntail\n".to_vec())
        );
    }

    #[test]
    fn task6_logical_line_cursor_has_constant_pointer_sized_state() {
        assert!(
            std::mem::size_of::<super::LogicalLineCursor<'_>>() <= 3 * std::mem::size_of::<usize>()
        );
    }

    #[test]
    fn task6_apply_streams_newline_dense_four_mib_base() {
        let base = b"x\n".repeat(super::MAX_PATCH_BYTES / 2);
        let patch = "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-x\n+y\n";
        let result = apply(Some(&base), patch).unwrap();
        let super::PatchedFile::Write(output) = result else {
            panic!("update returned delete");
        };
        assert_eq!(output.len(), base.len());
        assert_eq!(&output[..2], b"y\n");
        assert_eq!(&output[2..], &base[2..]);
    }
}
