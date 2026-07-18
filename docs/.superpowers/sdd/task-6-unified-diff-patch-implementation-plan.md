# Task 6 Restricted Unified-Diff Patch Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bounded restricted unified-diff parser, exact local text application, no-follow complete remote base snapshots, and sequential guarded multi-file patch application with truthful partial and unknown-outcome reporting.

**Architecture:** `src/remote/patch.rs` owns parsing, logical-line application, private complete-file snapshots, preparation, and sequential orchestration. `src/remote/mod.rs` exposes only request/result and `RemoteBridge::apply_patch`; `src/error.rs` carries optional patch progress on the original typed error. Every base and output is validated before Task 5 Create/Replace/guarded-delete runs in patch order.

**Tech Stack:** Rust 1.91.1 edition 2024, Tokio, `tokio-util::CancellationToken`, SHA-256 via `sha2`, Serde, existing private output spools, system OpenSSH through the existing fixed runner, POSIX sh plus probed GNU coreutils, fake SSH integration fixtures; no Python runtime or real-host mutation tests.

## Global Constraints

- Follow `docs/.superpowers/sdd/task-6-unified-diff-patch-design.md` exactly.
- Accept only `--- a/P` / `+++ b/P`, `/dev/null`, hunk headers, body records, and the exact no-newline marker; reject Git metadata, tab-delimited traditional timestamps, rename/mode/binary forms, comments, and blank separators. A space suffix in a header is literal filename text.
- V1 rejects empty-file Create/Delete because the accepted standard content-hunk language cannot represent them without a bridge-only extension.
- Final target snapshots are complete and no-follow; live/dangling symlinks and non-regular entries are rejected before mutation.
- Compiled ceilings are 4 MiB patch bytes, 32 files, 4,096 hunks, 100,000 body records, and 64 KiB per path.
- Aggregate complete base bytes and aggregate output bytes are each bounded by the host's effective `max_write_bytes`.
- All bases and outputs validate before the first mutation; mutations remain sequential and non-transactional.
- Preserve Task 5 error codes and exactly-once mutation behavior. Never retry or continue after any failure.
- A post-spawn ambiguous current path goes only in `outcome_unknown_paths`; it is never claimed changed or not changed.
- Do not mutate a real SSH host in tests. Use fake SSH plus temporary local directories.
- Do not move the Python prototype, add MCP/CLI schemas, or commit unrelated changes in Task 6.

## File Map

- Create `src/remote/patch.rs`: constants, parser types/state machine, logical-line application, snapshot fixed script/protocol, preparation, sequential mutation orchestration, and focused unit tests.
- Modify `src/remote/mod.rs`: declare the patch module, public request/result types, and `RemoteBridge::apply_patch` facade.
- Modify `src/error.rs`: optional patch progress fields on `ErrorDetails`.
- Modify `tests/remote_ops.rs`: public API, fake-SSH snapshot, all-base barrier, partial failure, cancellation, and unknown-outcome integration tests.
- Modify `tests/fixtures/fake-ssh.sh`: add a Task 6 phase log that distinguishes snapshot (`S`) from mutation (`M`) fixed commands without changing existing `P`/`C` logs.

---

### Task 1: Freeze Public Shapes and Patch Progress Fields

**Files:**
- Modify: `src/error.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: existing `RemoteContext`, `BridgeError`, and `CancellationToken`.
- Produces: `ApplyPatchRequest`, `ApplyPatchResult`, four optional progress fields in `ErrorDetails`, and the public `RemoteBridge::apply_patch` signature used by later tasks.

- [ ] **Step 1: Add the failing closed-shape test**

Add the imports and this focused test to `tests/remote_ops.rs`:

```rust
use codex_ssh_bridge::remote::{ApplyPatchRequest, ApplyPatchResult};

#[test]
fn task6_request_result_and_error_progress_shapes_are_closed() {
    let request = ApplyPatchRequest {
        host: "dev".to_owned(),
        patch: "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n".to_owned(),
    };
    assert_eq!(request.host, "dev");

    let result = ApplyPatchResult {
        context: context(),
        changed_paths: vec!["a".to_owned()],
    };
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::json!({
            "remote": true,
            "host": "dev",
            "physical_root": "/physical/root",
            "shell": {"kind": "sh", "version": null, "fallback": false},
            "changed_paths": ["a"]
        })
    );

    let error = BridgeError {
        code: ErrorCode::WriteConflict,
        message: "patch failed".to_owned(),
        retryable: false,
        details: codex_ssh_bridge::ErrorDetails {
            failed_path: Some("b".to_owned()),
            changed_paths: Some(vec!["a".to_owned()]),
            not_changed_paths: Some(vec!["b".to_owned(), "c".to_owned()]),
            outcome_unknown_paths: Some(Vec::new()),
            ..Default::default()
        },
    };
    let json = serde_json::to_value(error).unwrap();
    assert_eq!(json["details"]["failed_path"], "b");
    assert_eq!(json["details"]["changed_paths"], serde_json::json!(["a"]));
    assert_eq!(
        json["details"]["not_changed_paths"],
        serde_json::json!(["b", "c"])
    );
    assert_eq!(
        json["details"]["outcome_unknown_paths"],
        serde_json::json!([])
    );
}
```

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
cargo test --test remote_ops task6_request_result_and_error_progress_shapes_are_closed -- --exact --nocapture
```

Expected: compilation fails because `ApplyPatchRequest`, `ApplyPatchResult`, and the four `ErrorDetails` fields do not exist.

- [ ] **Step 3: Add the minimal public shapes**

Add to `ErrorDetails` with the existing Serde omission convention:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub failed_path: Option<String>,
#[serde(skip_serializing_if = "Option::is_none")]
pub changed_paths: Option<Vec<String>>,
#[serde(skip_serializing_if = "Option::is_none")]
pub not_changed_paths: Option<Vec<String>>,
#[serde(skip_serializing_if = "Option::is_none")]
pub outcome_unknown_paths: Option<Vec<String>>,
```

Add to `src/remote/mod.rs`:

```rust
mod patch;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPatchRequest {
    pub host: String,
    pub patch: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplyPatchResult {
    #[serde(flatten)]
    pub context: RemoteContext,
    pub changed_paths: Vec<String>,
}

impl RemoteBridge {
    pub async fn apply_patch(
        &self,
        request: ApplyPatchRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<ApplyPatchResult> {
        patch::apply_patch(self, request, cancel).await
    }
}
```

Create `src/remote/patch.rs` with this exact admission stub so the new public
surface compiles while subsequent tasks replace one behavior at a time:

```rust
use tokio_util::sync::CancellationToken;

use crate::error::{BridgeError, BridgeResult};

use super::{ApplyPatchRequest, ApplyPatchResult, RemoteBridge};

pub(super) async fn apply_patch(
    _bridge: &RemoteBridge,
    _request: ApplyPatchRequest,
    _cancel: CancellationToken,
) -> BridgeResult<ApplyPatchResult> {
    Err(BridgeError::invalid_argument(
        "restricted unified-diff parsing is not implemented",
    ))
}
```

- [ ] **Step 4: Run the shape test and existing error tests**

Run:

```bash
cargo test --test remote_ops task6_request_result_and_error_progress_shapes_are_closed -- --exact --nocapture
cargo test --lib error::tests -- --nocapture
```

Expected: both commands pass; existing serialized errors omit the new fields when `None`.

- [ ] **Step 5: Commit the independently reviewable API slice**

```bash
git add src/error.rs src/remote/mod.rs src/remote/patch.rs tests/remote_ops.rs
git commit -m "feat: define remote patch API progress shapes"
```

---

### Task 2: Parse the Closed Restricted Diff Language

**Files:**
- Modify: `src/remote/patch.rs`

**Interfaces:**
- Consumes: `BridgeResult`, `ErrorCode::{InvalidArgument, RequestTooLarge}`.
- Produces: `parse_patch(&str) -> BridgeResult<Vec<FilePatch>>` and the exact parser model from the design.

- [ ] **Step 1: Add RED parser tests inside `src/remote/patch.rs`**

Add a `#[cfg(test)]` module containing these exact positive cases:

```rust
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
    assert_eq!(parsed[1].hunks[0].new, super::HunkRange { start: 1, count: 1 });
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
```

Add table-driven negative coverage with these complete inputs and expected codes:

```rust
#[test]
fn task6_parse_rejects_every_non_language_form() {
    let cases = [
        ("", crate::ErrorCode::InvalidArgument),
        ("diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n", crate::ErrorCode::InvalidArgument),
        ("--- a/a\tstamp\n+++ b/a\tstamp\n@@ -1 +1 @@\n-a\n+b\n", crate::ErrorCode::InvalidArgument),
        ("--- a/a\n+++ b/b\n@@ -1 +1 @@\n-a\n+b\n", crate::ErrorCode::InvalidArgument),
        ("--- /dev/null\n+++ /dev/null\n@@ -0,0 +1 @@\n+x\n", crate::ErrorCode::InvalidArgument),
        ("--- a/../a\n+++ b/../a\n@@ -1 +1 @@\n-a\n+b\n", crate::ErrorCode::PathOutsideRoot),
        ("--- a/a//b\n+++ b/a//b\n@@ -1 +1 @@\n-a\n+b\n", crate::ErrorCode::InvalidArgument),
        ("--- a/a\n+++ b/a\n@@ -184467440737095516160 +1 @@\n-a\n+b\n", crate::ErrorCode::InvalidArgument),
        ("--- a/a\n+++ b/a\n@@ -1,2 +1 @@\n-a\n+b\n", crate::ErrorCode::InvalidArgument),
        ("--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n\\ no newline at end of file\n", crate::ErrorCode::InvalidArgument),
        ("--- /dev/null\n+++ b/empty\n@@ -0,0 +0,0 @@\n", crate::ErrorCode::InvalidArgument),
        ("GIT binary patch\n", crate::ErrorCode::InvalidArgument),
    ];
    for (input, code) in cases {
        assert_eq!(super::parse_patch(input).unwrap_err().code, code, "{input:?}");
    }
}
```

Add separate tests named:

- `task6_parse_rejects_duplicate_canonical_paths`
- `task6_parse_rejects_nonfinal_or_duplicate_no_newline_marker`
- `task6_parse_rejects_file_hunk_and_body_count_ceilings`
- `task6_parse_rejects_patch_and_path_byte_ceilings`

Use the exact constants from the design and checked builders so the tests do not allocate beyond 4 MiB plus one byte.

- [ ] **Step 2: Run parser tests and verify RED**

Run:

```bash
cargo test --lib remote::patch::tests::task6_parse -- --nocapture
```

Expected: compilation fails because the parser types and `parse_patch` do not exist.

- [ ] **Step 3: Implement the parser state machine**

Define the binding constants and types exactly:

```rust
const MAX_PATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_PATCH_FILES: usize = 32;
const MAX_PATCH_HUNKS: usize = 4_096;
const MAX_PATCH_BODY_LINES: usize = 100_000;
const MAX_PATCH_PATH_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilePatch {
    pub path: String,
    pub operation: FilePatchOperation,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilePatchOperation { Create, Update, Delete }

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hunk {
    pub old: HunkRange,
    pub new: HunkRange,
    pub lines: Vec<HunkLine>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HunkRange { pub start: usize, pub count: usize }

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HunkLine {
    pub kind: HunkLineKind,
    pub text: String,
    pub has_lf: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HunkLineKind { Context, Remove, Add }
```

Implement `parse_patch` as one explicit cursor over LF-delimited records. It must:

1. reject NUL and input over `MAX_PATCH_BYTES` before allocating parser vectors;
2. require an old header at file state, then an adjacent new header;
3. classify only the three valid header pairs and validate canonical paths;
4. reject a duplicate path with a `BTreeSet<String>`;
5. parse hunk headers with byte-prefix stripping and checked decimal helpers, not regex;
6. consume body records until both declared counts are satisfied;
7. attach an exact marker only to the immediately preceding body record;
8. reject a file with no add/remove, zero hunks, or a zero-change hunk;
9. reject any record remaining after a completed hunk unless it starts `@@ -` or `--- `; and
10. enforce aggregate file, hunk, and body-record ceilings with checked addition.

Use only fixed safe messages such as `"patch hunk header is invalid"`; never include patch text or a remote path in an error message.

- [ ] **Step 4: Run parser tests to GREEN and refactor without behavior changes**

Run:

```bash
cargo test --lib remote::patch::tests::task6_parse -- --nocapture
cargo clippy --lib --all-features -- -D warnings
```

Expected: every parser test passes and Clippy reports no warnings.

- [ ] **Step 5: Commit the parser slice**

```bash
git add src/remote/patch.rs
git commit -m "feat: parse restricted unified diffs"
```

---

### Task 3: Apply Hunks Exactly and Preserve Final-Newline State

**Files:**
- Modify: `src/remote/patch.rs`

**Interfaces:**
- Consumes: `FilePatch`, `BaseSnapshot`, and a per-file output byte ceiling.
- Produces: `apply_file_patch(&BaseSnapshot, &FilePatch, usize) -> BridgeResult<PatchedFile>`.

- [ ] **Step 1: Add RED logical-line and application tests**

Define a test helper that parses exactly one file and invokes application:

```rust
fn apply(base: Option<&[u8]>, patch: &str) -> crate::BridgeResult<super::PatchedFile> {
    let parsed = super::parse_patch(patch)?;
    assert_eq!(parsed.len(), 1);
    let snapshot = match base {
        Some(bytes) => super::BaseSnapshot::Regular {
            bytes: bytes.to_vec(),
            sha256: format!("{:x}", sha2::Sha256::digest(bytes)),
        },
        None => super::BaseSnapshot::Missing,
    };
    super::apply_file_patch(&snapshot, &parsed[0], 4 * 1024 * 1024)
}
```

Add these exact focused tests:

```rust
#[test]
fn task6_apply_preserves_untouched_terminal_lf_state() {
    let patch = "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\n";
    assert_eq!(apply(Some(b"old\ntail\n"), patch).unwrap(), super::PatchedFile::Write(b"new\ntail\n".to_vec()));
    assert_eq!(apply(Some(b"old\ntail"), patch).unwrap(), super::PatchedFile::Write(b"new\ntail".to_vec()));
}

#[test]
fn task6_apply_changes_terminal_lf_only_with_exact_markers() {
    let remove_lf = concat!(
        "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
        "-old\n",
        "+new\n\\ No newline at end of file\n",
    );
    assert_eq!(apply(Some(b"old\n"), remove_lf).unwrap(), super::PatchedFile::Write(b"new".to_vec()));

    let add_lf = concat!(
        "--- a/a\n+++ b/a\n@@ -1 +1 @@\n",
        "-old\n\\ No newline at end of file\n",
        "+new\n",
    );
    assert_eq!(apply(Some(b"old"), add_lf).unwrap(), super::PatchedFile::Write(b"new\n".to_vec()));
}

#[test]
fn task6_apply_supports_nonempty_create_update_to_empty_and_delete() {
    let create = "--- /dev/null\n+++ b/a\n@@ -0,0 +1 @@\n+x\n";
    assert_eq!(apply(None, create).unwrap(), super::PatchedFile::Write(b"x\n".to_vec()));

    let empty = "--- a/a\n+++ b/a\n@@ -1 +0,0 @@\n-x\n";
    assert_eq!(apply(Some(b"x\n"), empty).unwrap(), super::PatchedFile::Write(Vec::new()));

    let delete = "--- a/a\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n";
    assert_eq!(apply(Some(b"x\n"), delete).unwrap(), super::PatchedFile::Delete);
}
```

Add tests named:

- `task6_apply_validates_old_and_new_positions_not_only_counts`
- `task6_apply_rejects_overlapping_and_repeated_zero_anchor_hunks`
- `task6_apply_matches_context_removal_and_lf_state_byte_for_byte`
- `task6_apply_rejects_non_utf8_nul_and_wrong_base_presence`
- `task6_apply_rejects_delete_with_nonempty_output`
- `task6_apply_rejects_per_file_output_overflow_before_allocation`

Base mismatch must assert `WriteConflict`; malformed ranges and non-text bases must assert `InvalidArgument`; output overflow must assert `RequestTooLarge`.

- [ ] **Step 2: Run application tests and verify RED**

Run:

```bash
cargo test --lib remote::patch::tests::task6_apply -- --nocapture
```

Expected: compilation fails because `BaseSnapshot`, `PatchedFile`, and `apply_file_patch` do not exist.

- [ ] **Step 3: Implement logical lines and exact application**

Add:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
enum BaseSnapshot {
    Missing,
    Regular { bytes: Vec<u8>, sha256: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatchedFile {
    Write(Vec<u8>),
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogicalLine<'a> {
    text: &'a str,
    has_lf: bool,
}
```

Implement one splitter that yields no artificial empty record after terminal LF. Convert the base with `std::str::from_utf8`, reject NUL, then apply hunks with two cursors:

- `base_cursor`: next logical base line;
- `output_line_count`: logical lines already emitted.

For positive ranges require `start - 1` to equal the cursor at hunk entry after copying the unchanged gap. For zero ranges require `start` to equal that cursor. Validate the new range against `output_line_count` with the same rule. Before extending the output, use checked byte arithmetic against `maximum_output_bytes`. Compare body text and `has_lf` for Context/Remove. Append LF only when `has_lf` is true.

After the last hunk, copy the untouched suffix and enforce the operation postconditions from the design. Return fixed local errors with no base content in messages.

- [ ] **Step 4: Run application and parser tests to GREEN**

Run:

```bash
cargo test --lib remote::patch::tests -- --nocapture
cargo fmt --check
```

Expected: all Task 6 unit tests pass and formatting is clean.

- [ ] **Step 5: Commit the local application slice**

```bash
git add src/remote/patch.rs
git commit -m "feat: apply text patch hunks exactly"
```

---

### Task 4: Snapshot Every Base Completely Without Following the Final Entry

**Files:**
- Modify: `src/remote/patch.rs`
- Modify: `tests/remote_ops.rs`
- Modify: `tests/fixtures/fake-ssh.sh`

**Interfaces:**
- Consumes: resolved `RemotePath`, existing fixed read-only runner, private spools, `safe_write` no-follow capability, host command timeout.
- Produces: complete `BaseSnapshot` values with stable SHA-256 and no truncation or line limit.

- [ ] **Step 1: Add RED no-follow and complete-read integration tests**

Add these public-operation tests to `tests/remote_ops.rs`; at this stage they
fail because `apply_patch` still returns the admission-stub rejection:

- `task6_snapshot_rejects_live_and_dangling_final_symlinks_before_mutation`
- `task6_snapshot_rejects_directory_fifo_and_special_mode_regular_file_before_mutation`
- `task6_snapshot_detects_identity_or_hash_change_as_read_conflict`
- `task6_snapshot_missing_is_distinct_from_existing_empty_regular_file`
- `task6_snapshot_cancelled_before_mutation_reports_all_paths_not_changed`

Also add the RED unit test
`task6_snapshot_protocol_accepts_1_048_577_complete_bytes` inside
`src/remote/patch.rs`. Build a `Vec<u8>` of exactly 1,048,577 bytes, compute its
lowercase SHA-256, construct the exact SUCCESS metadata record with matching
size/hash/mode/device/inode/link count, and call the not-yet-existing strict
snapshot-protocol parser. Assert that the returned regular snapshot owns every
byte and the same digest.

For the symlink test, create `first` as a normal file and make the second target both a live and dangling symlink in separate fixtures. Apply a two-file patch and assert:

```rust
assert_eq!(error.code, ErrorCode::WriteConflict);
assert_eq!(std::fs::read(remote.path().join("first")).unwrap(), b"old\n");
assert_eq!(error.details.changed_paths, Some(Vec::new()));
assert_eq!(
    error.details.not_changed_paths,
    Some(vec!["first".to_owned(), "second".to_owned()])
);
assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
```

Add `FAKE_SSH_TASK6_PHASE_LOG` to `tests/fixtures/fake-ssh.sh`. For a
`local-fixed` command, append `S` when the rendered command contains the unique
`codex_patch_snapshot` function name and append `M` when it contains the Task 5
write or guarded-delete producer sentinel. Do not alter existing `P`/`C`
logging. Use this log plus PATH shims for deterministic races. Assert no `M`
record exists before every snapshot test reaches its expected result.

- [ ] **Step 2: Run snapshot tests and verify RED**

Run:

```bash
cargo test --test remote_ops task6_snapshot -- --nocapture
cargo test --lib remote::patch::tests::task6_snapshot_protocol_accepts_1_048_577_complete_bytes -- --exact --nocapture
```

Expected: integration tests fail with the admission-stub `InvalidArgument`,
and the unit test fails compilation because the strict snapshot-protocol
parser does not exist; no remote file changes.

- [ ] **Step 3: Implement the fixed snapshot protocol**

Add `PATCH_SNAPSHOT_SCRIPT` to `src/remote/patch.rs`. Its closed stdout is raw file bytes; its closed stderr record is one of:

```text
STATUS=MISSING\0
STATUS=WRITE_CONFLICT\0
STATUS=NOT_FOUND\0
STATUS=NOT_DIRECTORY\0
STATUS=PERMISSION_DENIED\0
STATUS=REQUEST_TOO_LARGE\0
STATUS=READ_CONFLICT\0
STATUS=SUCCESS\0SIZE=<decimal>\0SHA256=<64 lowercase hex>\0MODE=<octal>\0DEVICE=<decimal>\0INODE=<decimal>\0LINKS=<decimal>\0
CODE=CAPABILITY_MISMATCH\0CAPABILITY=safe_write\0
```

The static script takes exactly parent, basename, and bounded decimal budget.
It must bind and enter the parent with the same followed-stat, post-`cd`
device/inode check, and inaccessible-ancestor classification as Task 5, then
address only `./<basename>`. It reports Missing only after the bound parent
exists and `[ ! -e "$target" ] && [ ! -L "$target" ]`; a missing,
non-directory, or inaccessible parent retains its typed error before mutation.
Reject every final symlink/non-regular/special-mode entry and use the Task 5
production-probed no-follow input form for pre-hash, raw transfer, and
post-hash. Re-lstat after transfer and require identical
device/inode/type/mode/size/link count. Emit the closed ReadConflict result on
identity/hash drift. Rust hashes the captured bytes and requires exact equality
with the reported digest.

Implement:

```rust
async fn snapshot_base(
    bridge: &RemoteBridge,
    host: &str,
    path: &RemotePath,
    remaining_bytes: usize,
    cancel: CancellationToken,
) -> BridgeResult<(RemoteContext, BaseSnapshot)>;
```

Use `FixedOperationKind::ReadOnly`, `InternalSpoolOwner`, stdout limit `remaining_bytes + 1`, a small fixed stderr limit, and `execute_readonly_fixed`. Parse the record strictly. Any malformed metadata, unexpected stdout for Missing/domain results, or hash/size mismatch is `ProtocolError`. A stable content mismatch across the two hashes is `ReadConflict`.

- [ ] **Step 4: Replace only enough facade logic to exercise snapshots**

In `apply_patch`, perform host/read-only/patch-byte validation, parse and resolve
all paths, then snapshot all targets. After successful snapshots, return the
same exact admission-stub error until the next plan task adds complete
preparation. Decorate snapshot failures with empty changed/unknown lists and
every parsed path in `not_changed_paths`.

- [ ] **Step 5: Run snapshot tests to GREEN**

Run:

```bash
cargo test --test remote_ops task6_snapshot -- --nocapture
cargo test --lib remote::patch::tests -- --nocapture
```

Expected: snapshot rejection, conflict, and cancellation tests pass, and the
unit protocol test verifies all `1_048_577` captured bytes without truncation.
The end-to-end large-base success test is added with sequential mutation in
Task 6 of this plan.

- [ ] **Step 6: Commit the snapshot slice**

```bash
git add src/remote/patch.rs tests/remote_ops.rs tests/fixtures/fake-ssh.sh
git commit -m "feat: snapshot patch bases without following targets"
```

---

### Task 5: Validate All Bases and Outputs Before the First Mutation

**Files:**
- Modify: `src/remote/patch.rs`
- Modify: `tests/remote_ops.rs`
- Modify: `tests/fixtures/fake-ssh.sh`

**Interfaces:**
- Consumes: parsed patches, resolved paths, `BaseSnapshot`, `apply_file_patch`, effective host limits.
- Produces: a complete ordered `Vec<PreparedMutation>` before mutation begins.

- [ ] **Step 1: Add RED preparation-barrier tests**

Add:

- `task6_invalid_binary_traversal_duplicate_and_read_only_launch_zero_ssh`
- `task6_second_base_mismatch_leaves_first_file_unchanged`
- `task6_second_output_over_limit_leaves_first_file_unchanged`
- `task6_all_snapshots_finish_before_any_mutation_starts`
- `task6_aggregate_base_and_output_bounds_fail_before_mutation`
- `task6_empty_create_and_delete_are_rejected_locally_by_v1_policy`

The all-snapshot barrier test must use three paths and a deterministic log with distinct snapshot (`S`) and mutation (`M`) markers. Assert the first mutation marker occurs only after three snapshot markers:

```rust
let phases = std::fs::read_to_string(&phase_log).unwrap();
assert_eq!(phases.lines().collect::<Vec<_>>(), ["S", "S", "S", "M", "M", "M"]);
```

The second-base mismatch test makes file one patch-valid and file two patch-stale. Assert zero mutation markers, both files unchanged, `WriteConflict`, and both paths in `not_changed_paths`.

- [ ] **Step 2: Run preparation tests and verify RED**

Run:

```bash
cargo test --test remote_ops task6_all_ -- --nocapture
cargo test --test remote_ops task6_second_base_mismatch_leaves_first_file_unchanged -- --exact --nocapture
cargo test --test remote_ops task6_aggregate_base_and_output_bounds_fail_before_mutation -- --exact --nocapture
```

Expected: tests fail because preparation does not yet apply every file or produce mutations.

- [ ] **Step 3: Implement complete preparation**

Add:

```rust
enum PreparedAction {
    Create { content: String },
    Replace { content: String, expected_sha256: String },
    Delete { expected_sha256: String },
}

struct PreparedMutation {
    path: String,
    action: PreparedAction,
}
```

Preparation must:

1. resolve host and reject read-only before capability/SSH work;
2. require patch bytes within both `MAX_PATCH_BYTES` and effective `max_write_bytes`;
3. parse every file and resolve every canonical relative path;
4. snapshot every path, decrementing a checked aggregate base budget;
5. after all snapshots succeed, call `apply_file_patch` for every pair;
6. check each output and checked aggregate output against effective `max_write_bytes`;
7. convert UTF-8 output bytes to owned `String` without Base64 duplication;
8. map operation/output to the exact prepared action; and
9. check cancellation after preparation and before returning the vector.

Any failure decorates the original error with `changed_paths=[]`,
`outcome_unknown_paths=[]`, and all parsed paths in `not_changed_paths`.

- [ ] **Step 4: Run preparation tests to GREEN**

Run:

```bash
cargo test --test remote_ops task6_invalid_binary_traversal_duplicate_and_read_only_launch_zero_ssh -- --exact --nocapture
cargo test --test remote_ops task6_second_base_mismatch_leaves_first_file_unchanged -- --exact --nocapture
cargo test --test remote_ops task6_second_output_over_limit_leaves_first_file_unchanged -- --exact --nocapture
cargo test --test remote_ops task6_all_snapshots_finish_before_any_mutation_starts -- --exact --nocapture
cargo test --test remote_ops task6_aggregate_base_and_output_bounds_fail_before_mutation -- --exact --nocapture
```

Expected: every preparation barrier passes and no test has yet required partial mutation behavior.

- [ ] **Step 5: Commit the preparation barrier**

```bash
git add src/remote/patch.rs tests/remote_ops.rs tests/fixtures/fake-ssh.sh
git commit -m "feat: prepare every patch mutation before writing"
```

---

### Task 6: Execute Sequential Guarded Mutations and Report Exact Progress

**Files:**
- Modify: `src/remote/patch.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Consumes: complete ordered `PreparedMutation`, Task 5 `write` and crate-private `guarded_delete`.
- Produces: successful `ApplyPatchResult` or the original `BridgeError` decorated with a complete three-way path partition.

- [ ] **Step 1: Add RED success and definite-partial-failure tests**

Add:

- `task6_create_update_and_delete_execute_in_patch_order`
- `task6_snapshot_reads_complete_base_above_public_one_mib_read_ceiling`
- `task6_update_to_empty_uses_replace_not_delete`
- `task6_second_definite_failure_reports_exact_changed_and_not_changed_paths`
- `task6_late_expected_hash_race_returns_partial_write_conflict`
- `task6_failure_stops_before_every_later_mutation`

For the success test, prepare three nonempty operations and assert:

```rust
assert_eq!(result.changed_paths, ["created", "updated", "deleted"]);
assert_eq!(std::fs::read(remote.path().join("created")).unwrap(), b"created\n");
assert_eq!(std::fs::read(remote.path().join("updated")).unwrap(), b"new\n");
assert!(!remote.path().join("deleted").exists());
```

For `task6_snapshot_reads_complete_base_above_public_one_mib_read_ceiling`,
use `1_048_577` bytes while remaining below the host's 4 MiB write ceiling.
Patch a line near the beginning and assert the complete suffix and final
SHA-256 are preserved. This proves the orchestrator does not call the
truncating public read facade.

For a deterministic definite failure on the second mutation, race the second Create target into existence before its Task 5 hard-link install. Assert:

```rust
assert_eq!(error.code, ErrorCode::WriteConflict);
assert_eq!(error.details.failed_path.as_deref(), Some("second"));
assert_eq!(error.details.changed_paths, Some(vec!["first".to_owned()]));
assert_eq!(
    error.details.not_changed_paths,
    Some(vec!["second".to_owned(), "third".to_owned()])
);
assert_eq!(error.details.outcome_unknown_paths, Some(Vec::new()));
```

- [ ] **Step 2: Run mutation tests and verify RED**

Run:

```bash
cargo test --test remote_ops task6_create_update_and_delete_execute_in_patch_order -- --exact --nocapture
cargo test --test remote_ops task6_second_definite_failure_reports_exact_changed_and_not_changed_paths -- --exact --nocapture
```

Expected: tests fail because prepared actions are not yet executed.

- [ ] **Step 3: Implement sequential execution**

For each prepared action, build one future exactly as follows and retain the
returned result for outer progress classification:

```rust
let operation_result = match action {
    PreparedAction::Create { content } => {
        bridge.write(
            WriteRequest {
                host: host.clone(),
                path: path.clone(),
                content,
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Create,
            },
            cancel.clone(),
        ).await.map(|result| result.context)
    }
    PreparedAction::Replace { content, expected_sha256 } => {
        bridge.write(
            WriteRequest {
                host: host.clone(),
                path: path.clone(),
                content,
                encoding: WriteEncoding::Utf8,
                mode: WriteMode::Replace { expected_sha256: Some(expected_sha256) },
            },
            cancel.clone(),
        ).await.map(|result| result.context)
    }
    PreparedAction::Delete { expected_sha256 } => {
        bridge.guarded_delete(
            GuardedDeleteRequest {
                host: host.clone(),
                path: path.clone(),
                expected_sha256,
            },
            cancel.clone(),
        ).await.map(|_| preparation_context.clone())
    }
};
```

Match `operation_result` so the original error can be decorated before return.
Push `path` into `changed_paths` only after confirmed success. On a definite
error, set `failed_path`, the confirmed prefix, current-plus-suffix
`not_changed_paths`, and an empty unknown list. Stop immediately.

Retain `preparation_context` from the first successful base snapshot and require
later snapshots to report the same host and physical root. Use it for the
successful `ApplyPatchResult`, including an all-delete patch because the
crate-private delete result has no context. The parser forbids an empty patch,
so preparation always has a context.

- [ ] **Step 4: Run sequential success and definite-failure tests to GREEN**

Run:

```bash
cargo test --test remote_ops task6_create_update_and_delete_execute_in_patch_order -- --exact --nocapture
cargo test --test remote_ops task6_update_to_empty_uses_replace_not_delete -- --exact --nocapture
cargo test --test remote_ops task6_second_definite_failure_reports_exact_changed_and_not_changed_paths -- --exact --nocapture
cargo test --test remote_ops task6_late_expected_hash_race_returns_partial_write_conflict -- --exact --nocapture
cargo test --test remote_ops task6_failure_stops_before_every_later_mutation -- --exact --nocapture
```

Expected: all pass; log counts prove one mutation attempt per attempted file and zero attempts after failure.

- [ ] **Step 5: Commit sequential guarded apply**

```bash
git add src/remote/patch.rs tests/remote_ops.rs
git commit -m "feat: apply prepared remote patches sequentially"
```

---

### Task 7: Preserve Cancellation and Unknown-Outcome Truthfulness

**Files:**
- Modify: `src/remote/patch.rs`
- Modify: `tests/remote_ops.rs`
- Modify: `tests/fixtures/fake-ssh.sh`

**Interfaces:**
- Consumes: Task 5's pre-spawn `Cancelled` and post-spawn `MutationOutcomeUnknown` distinction.
- Produces: exact `changed_paths`, `not_changed_paths`, and `outcome_unknown_paths` for cancellation and ambiguous failure.

- [ ] **Step 1: Add RED cancellation and unknown tests**

Add:

- `task6_cancel_during_snapshot_reports_all_paths_not_changed`
- `task6_cancel_after_preparation_before_first_mutation_changes_nothing`
- `task6_cancel_between_mutations_reports_confirmed_prefix`
- `task6_cancel_before_current_mutation_spawn_keeps_current_not_changed`
- `task6_cancel_after_current_mutation_spawn_marks_only_current_unknown`
- `task6_second_protocol_or_disconnect_unknown_stops_without_retry`

Use deterministic ready files rather than sleeps. For post-spawn cancellation,
block Task 5 staging `dd`, wait for its ready marker, cancel the shared token,
and assert:

```rust
assert_eq!(error.code, ErrorCode::MutationOutcomeUnknown);
assert_eq!(error.details.mutation_may_have_applied, Some(true));
assert_eq!(error.details.failed_path.as_deref(), Some("second"));
assert_eq!(error.details.changed_paths, Some(vec!["first".to_owned()]));
assert_eq!(error.details.not_changed_paths, Some(vec!["third".to_owned()]));
assert_eq!(
    error.details.outcome_unknown_paths,
    Some(vec!["second".to_owned()])
);
```

For pre-spawn cancellation, occupy the per-host semaphore with a controllable
operation, start the patch mutation, cancel while queued, and require
`Cancelled` with current-plus-suffix in `not_changed_paths` and no unknown
path. For malformed/disconnect post-commit fixtures, require exactly one child
for the current path and zero later mutation children.

- [ ] **Step 2: Run cancellation tests and verify RED**

Run:

```bash
cargo test --test remote_ops task6_cancel -- --nocapture
cargo test --test remote_ops task6_second_protocol_or_disconnect_unknown_stops_without_retry -- --exact --nocapture
```

Expected: at least the unknown partition is wrong because the current error decorator still treats every failure as definite.

- [ ] **Step 3: Implement phase-aware progress decoration**

Before each mutation, check `cancel.is_cancelled()` and return a new
`Cancelled` error decorated with the confirmed prefix and current-plus-suffix
not changed.

After a Task 5 call returns an error, classify ambiguity only from the stable
Task 5 detail:

```rust
let unknown = error.details.mutation_may_have_applied == Some(true)
    || error.code == ErrorCode::MutationOutcomeUnknown;
```

When `unknown` is true:

- preserve the exact error code/message/retryability/details;
- set current path as `failed_path` and sole `outcome_unknown_paths` member;
- keep only the strict suffix in `not_changed_paths`; and
- never retry, inspect, or continue.

Otherwise current path joins the suffix in `not_changed_paths` and the unknown
list is empty. Do not convert a pre-spawn `Cancelled`, resolve error, probe
error, or closed Task 5 domain result into unknown.

- [ ] **Step 4: Run cancellation and unknown tests to GREEN**

Run:

```bash
cargo test --test remote_ops task6_cancel -- --nocapture
cargo test --test remote_ops task6_second_protocol_or_disconnect_unknown_stops_without_retry -- --exact --nocapture
cargo test --test remote_ops task5_ -- --nocapture
```

Expected: all Task 6 cancellation tests pass and Task 5's own unknown-outcome contract remains unchanged.

- [ ] **Step 5: Commit cancellation semantics**

```bash
git add src/remote/patch.rs tests/remote_ops.rs tests/fixtures/fake-ssh.sh
git commit -m "fix: report ambiguous patch outcomes truthfully"
```

---

### Task 8: Close Adversarial Coverage and Run the Task 6 Gate

**Files:**
- Modify: `src/remote/patch.rs`
- Modify: `tests/remote_ops.rs`
- Modify: `tests/fixtures/fake-ssh.sh`

**Interfaces:**
- Consumes: complete Task 6 implementation.
- Produces: review-ready parser, snapshot, orchestration, and regression evidence.

- [ ] **Step 1: Add the final adversarial matrix before any cleanup refactor**

Ensure named tests exist for every binding family:

```text
task6_parse_accepts_multiple_files_hunks_and_terminal_eof
task6_parse_freezes_no_newline_marker_on_the_preceding_side
task6_parse_rejects_every_non_language_form
task6_parse_rejects_duplicate_canonical_paths
task6_parse_rejects_nonfinal_or_duplicate_no_newline_marker
task6_parse_rejects_file_hunk_and_body_count_ceilings
task6_parse_rejects_patch_and_path_byte_ceilings
task6_apply_preserves_untouched_terminal_lf_state
task6_apply_changes_terminal_lf_only_with_exact_markers
task6_apply_supports_nonempty_create_update_to_empty_and_delete
task6_apply_validates_old_and_new_positions_not_only_counts
task6_apply_matches_context_removal_and_lf_state_byte_for_byte
task6_snapshot_rejects_live_and_dangling_final_symlinks_before_mutation
task6_snapshot_reads_complete_base_above_public_one_mib_read_ceiling
task6_snapshot_detects_identity_or_hash_change_as_read_conflict
task6_all_snapshots_finish_before_any_mutation_starts
task6_second_base_mismatch_leaves_first_file_unchanged
task6_second_definite_failure_reports_exact_changed_and_not_changed_paths
task6_cancel_after_current_mutation_spawn_marks_only_current_unknown
task6_second_protocol_or_disconnect_unknown_stops_without_retry
```

If any name is missing, write that test first and run it alone to observe RED
before changing production code.

- [ ] **Step 2: Run all Task 6 tests**

Run:

```bash
cargo test task6_ -- --nocapture
```

Expected: every Task 6 unit and integration test passes; no real SSH host is referenced.

- [ ] **Step 3: Run formatting and lint gates**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: both commands exit zero with no warnings.

- [ ] **Step 4: Run the complete relevant regression suites**

Run:

```bash
cargo test --test remote_ops -- --nocapture
cargo test --test ssh_transport -- --nocapture
cargo test --all-targets
```

Expected: every test passes, including all Task 4 reads and Task 5 write/delete security regressions.

- [ ] **Step 5: Run static scope and diff checks**

Run:

```bash
rg -n "diff --git|GIT binary patch|Binary files|outcome_unknown_paths|PATCH_SNAPSHOT_SCRIPT|guarded_delete|WriteMode::Replace" src/remote src/error.rs tests/remote_ops.rs
rg -n "python|sshfs|mount" src/remote/patch.rs
git diff --check
git status --short
```

Expected:

- accepted/rejected markers appear only in parser logic and tests;
- unknown progress, snapshot, expected-hash replace, and guarded delete are visible;
- no Python/SSHFS/mount implementation entered Task 6;
- `git diff --check` exits zero; and
- status lists only intended Task 6 files plus the user's pre-existing pycache directories.

- [ ] **Step 6: Review the implementation against the expanded design line by line**

Confirm all of these are true from code and tests:

- no empty-file Create/Delete extension slipped in;
- every parsed path is canonical and unique;
- every no-newline marker affects only the immediately preceding final line;
- no public read truncation path supplies a patch base;
- no mutation begins before every base and output validates;
- the current ambiguous path appears in neither changed nor not-changed lists;
- no failure starts a later mutation; and
- no Task 5 mutation is retried.

- [ ] **Step 7: Commit Task 6**

```bash
git add src/error.rs src/remote/mod.rs src/remote/patch.rs tests/remote_ops.rs tests/fixtures/fake-ssh.sh
git commit -m "feat: add guarded remote patch application"
```

Do not add `ssh_bridge/__pycache__/` or `tests/__pycache__/`.
