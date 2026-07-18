# Task 6 Expanded Design: Restricted Unified-Diff Patch Engine

Date: 2026-07-18

Status: Binding Task 6 implementation contract; implementation has not started

## 1. Relationship to the Approved Design and Main Plan

This document expands Task 6 of:

- `docs/superpowers/specs/2026-07-18-codex-ssh-bridge-rust-design.md`; and
- `docs/superpowers/plans/2026-07-18-codex-ssh-bridge-rust.md`.

It does not change the approved product boundary. `remote_apply_patch` remains
a local parser and in-memory text patcher followed by sequential per-file
guarded remote mutations. It is not transactionally atomic across files, does
not install a remote helper, does not treat the configured root as a symlink
sandbox, and does not add an MCP schema or CLI command in Task 6.

The expansion freezes points that the main plan leaves implicit: the accepted
diff language, final-newline representation, a no-follow complete-file base
snapshot, exact resource ceilings, partial-failure representation, and
cancellation behavior.

## 2. Scope

Task 6 adds:

- `src/remote/patch.rs` containing the restricted parser, local application,
  complete-file snapshot, and orchestration helpers;
- public request/result types plus `RemoteBridge::apply_patch` in
  `src/remote/mod.rs`;
- optional patch-progress fields in `ErrorDetails` in `src/error.rs`; and
- unit and fake-SSH integration coverage in `tests/remote_ops.rs`.

Task 6 consumes Task 5 exactly as implemented:

- `RemoteBridge::write` for create and expected-hash replace;
- crate-private `RemoteBridge::guarded_delete` for delete;
- no mutation retry;
- `MutationOutcomeUnknown` after a mutation child may have started; and
- final-target symlink rejection and guarded, same-directory replacement.

Task 6 does not add rename, copy, mode changes, binary patches, Git binary
payloads, parent creation, empty-file create/delete extensions, rollback, or
parallel mutations.

## 3. Architecture and Data Flow

`RemoteBridge::apply_patch` has four phases:

1. **Local admission.** Resolve the host, enforce read-only and request limits,
   parse the entire patch, reject duplicate/noncanonical paths, and resolve all
   paths beneath the configured root. Invalid local input starts no SSH
   process.
2. **Read-only preparation.** Snapshot every target completely with final-entry
   no-follow semantics. Every expected base state, byte sequence, and SHA-256
   is known before the first mutation.
3. **Local application.** Apply every hunk in memory, validate every context and
   deletion byte-for-byte, and validate all aggregate output limits. No write
   begins until every output is ready.
4. **Sequential guarded mutation.** In patch order, call Task 5 Create,
   expected-hash Replace, or guarded delete. Record a path only after confirmed
   success and stop at the first failure.

This ordering prevents a malformed later file or an already-stale later base
from causing an earlier file to change. It does not create a global
transaction. A base may race after preparation; the Task 5 expected-hash or
no-clobber guard then produces a precise partial failure.

## 4. Public and Internal Types

The public Task 6 surface is:

```rust
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
```

Patch paths are valid UTF-8 by grammar, so progress paths use `String` rather
than `EncodedValue`. They are configured-root-relative, canonical, and ordered
as they appear in the patch.

The parser and application model is:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePatch {
    pub path: String,
    pub operation: FilePatchOperation,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePatchOperation {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    pub old: HunkRange,
    pub new: HunkRange,
    pub lines: Vec<HunkLine>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HunkRange {
    pub start: usize,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HunkLine {
    pub kind: HunkLineKind,
    pub text: String,
    pub has_lf: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HunkLineKind {
    Context,
    Remove,
    Add,
}

enum BaseSnapshot {
    Missing,
    Regular {
        bytes: Vec<u8>,
        sha256: String,
    },
}

enum PatchedFile {
    Write(Vec<u8>),
    Delete,
}
```

The planned interfaces are:

```rust
pub fn parse_patch(input: &str) -> BridgeResult<Vec<FilePatch>>;

fn apply_file_patch(
    base: &BaseSnapshot,
    patch: &FilePatch,
    maximum_output_bytes: usize,
) -> BridgeResult<PatchedFile>;

impl RemoteBridge {
    pub async fn apply_patch(
        &self,
        request: ApplyPatchRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<ApplyPatchResult>;
}
```

`BaseSnapshot` deliberately distinguishes a missing target from an existing
empty file. A bare `&[u8]` would lose that distinction and could accidentally
permit Create over an existing empty file.

## 5. Restricted Unified-Diff Grammar

### 5.1 Record framing

Input is already UTF-8 because the public request carries a Rust `String`.
The parser rejects NUL anywhere. Syntax records are separated only by byte LF
(`\n`). The final syntax record may end at EOF instead of LF. The parser does
not strip CR. CR is invalid in headers, paths, hunk headers, marker records, and
section text; inside a context/add/remove payload it is an ordinary text byte,
which permits an LF-framed patch to describe CRLF file content deliberately.

The accepted grammar is:

```text
patch       := file_patch file_patch*
file_patch  := old_header LF new_header LF hunk hunk*
old_header  := "--- " old_path
new_header  := "+++ " new_path
old_path    := "/dev/null" | "a/" relative_path
new_path    := "/dev/null" | "b/" relative_path

hunk        := hunk_header LF hunk_record*
hunk_header := "@@ -" range " +" range " @@" [" " section]
range       := unsigned_decimal ["," unsigned_decimal]

hunk_record := " " text LF
             | "-" text LF
             | "+" text LF
             | "\\ No newline at end of file" LF
```

`section`, when present, contains at least one non-NUL, non-CR, non-LF Unicode
scalar and is ignored semantically. A trailing single space after the closing
`@@` is invalid.

The parser accepts no other record. In particular it rejects:

- `diff --git`, `index`, old/new mode, similarity, rename, or copy metadata;
- tab-delimited timestamp headers emitted by traditional `diff -u`;
- quoted/escaped Git path syntax;
- `GIT binary patch` and `Binary files ... differ`; and
- comments, blank separators, email preambles, or trailing prose.

This is intentionally narrower than arbitrary output from `git diff`. It is a
closed Agent-to-bridge language whose security and newline behavior can be
tested exhaustively. Task 8 must describe the same restriction in the MCP tool
schema and Skill.

### 5.2 File headers and operations

Header pairs map to operations as follows:

| Old header | New header | Operation |
|---|---|---|
| `--- a/P` | `+++ b/P` | Update, only when both `P` values are identical |
| `--- /dev/null` | `+++ b/P` | Create |
| `--- a/P` | `+++ /dev/null` | Delete |

Both paths as `/dev/null`, mismatched update paths, wrong `a/` or `b/`
prefixes, or any other pairing are `InvalidArgument`.

`relative_path` is the complete remainder after `a/` or `b/`; there is no
separate timestamp field. It must:

- be nonempty and at most 65,536 UTF-8 bytes;
- not begin with `/`;
- contain no NUL, horizontal tab, CR, or LF;
- contain no empty, `.` or `..` slash-separated component; and
- be unique across the complete patch.

Spaces, Unicode, quotes, backslashes, wildcard text, dollar signs,
backticks, command-substitution text, and leading hyphens are allowed. The
canonical-component restriction prevents two spellings of the same target and
rejects traversal even when lexical normalization would remain under the root.
Every accepted path is still passed through `RemotePath::resolve` before I/O.
A space-separated suffix that resembles a timestamp is therefore a literal
part of the filename; Task 6 neither recognizes nor discards it.

A `..` component is reported as `PathOutsideRoot`, matching the bridge's
existing lexical-escape contract. Other noncanonical path shapes are
`InvalidArgument`.

### 5.3 Hunk ranges

An omitted count means one. Decimal fields are nonempty ASCII digits, parsed
with checked arithmetic, and converted to `usize` with overflow rejection.
Leading zeros are accepted because they do not create an alternate path or
semantic interpretation.

For a positive count, start is one-based and must be positive. For a zero
count, start is an insertion anchor after line `start`; zero means before the
first line. Thus `-0,0` is the normal old range for a create, and `+0,0` is the
normal new range for a delete.

For every hunk:

- context plus removal records exactly equals the old count;
- context plus addition records exactly equals the new count;
- the old start agrees with the current base cursor;
- the new start agrees with the current output cursor;
- old ranges are strictly ordered and non-overlapping;
- repeated zero-count anchors are rejected rather than assigned an
  order-dependent interpretation; and
- at least one addition or removal exists in every file patch.

A hunk header cannot be accepted merely because its body counts happen to fit;
both old and new declared positions are validated during application.

### 5.4 No-newline marker

Every context, removal, or addition record denotes a logical file line. It has
`has_lf=true` unless immediately followed by the exact record:

```text
\ No newline at end of file
```

The marker is not counted in either range. It modifies the immediately
preceding record as follows:

- after a removal, the old-side line has no LF;
- after an addition, the new-side line has no LF; and
- after context, both old and new sides have no LF.

The marker may occur only once after a body record. A marked record must be the
final logical line on every side it affects, in the final hunk for that side.
An orphan, duplicate, nonfinal, misspelled, or whitespace-varied marker is
invalid. Context and removal comparison includes `has_lf`, so a patch cannot
silently match `text` against `text\n` or vice versa.

### 5.5 Empty-file create/delete v1 policy

V1 rejects a file patch with no hunk and rejects a zero-change hunk such as
`@@ -0,0 +0,0 @@`. Therefore an empty missing file cannot be created and an
existing empty file cannot be deleted through `remote_apply_patch` in Task 6.

The reason is representational, not a remote-write limitation: the required
header-plus-hunk restricted unified-diff language has no standard content hunk
that distinguishes those operations. Git expresses them with mode/index
metadata, which this closed grammar rejects. Inventing a bridge-only zero-hunk
extension would make the input no longer a restricted standard unified diff
and would create two encodings for future Task 8 documentation.

An empty file can still be created with `remote_write`. Empty-file deletion can
be considered in a later, separately specified extension or delete tool. V1
does support updating a nonempty existing file to empty, because removals are
an ordinary content hunk.

## 6. Local Application Semantics

Base bytes must be valid UTF-8 and contain no NUL. Otherwise a text patch is
rejected with `InvalidArgument` before mutation. Untouched CR bytes are
preserved; a hunk that matches a CRLF line includes the CR at the end of its
body text.

The application algorithm splits the base into logical `{ text, has_lf }`
records without manufacturing an extra empty line after a terminal LF:

- empty bytes contain zero logical lines;
- `a\n` contains one LF-terminated line;
- `a` contains one non-LF-terminated line; and
- `\n` contains one empty LF-terminated line.

For each hunk, copy the unchanged gap byte-for-byte, then process body records:

- Context consumes and re-emits one exactly matching base line.
- Remove consumes one exactly matching base line and emits nothing.
- Add consumes no base line and emits its payload with its declared LF state.

After the final hunk, copy the untouched suffix byte-for-byte. This preserves
the base's final-newline state unless the patch explicitly changes the final
line using the exact marker.

A stable base whose content or newline state does not match the patch is
`WriteConflict`, not malformed syntax. Syntax, impossible operation shape,
non-text base, and declared-range inconsistency are `InvalidArgument`.

Operation postconditions are:

- Create requires `BaseSnapshot::Missing` and produces `PatchedFile::Write`
  with nonempty bytes.
- Update requires `BaseSnapshot::Regular`, may produce empty bytes, and must
  actually add or remove content.
- Delete requires `BaseSnapshot::Regular` and must produce exactly empty bytes,
  then produces `PatchedFile::Delete`.

## 7. No-Follow Complete Base Snapshot

The public `RemoteBridge::read` is not suitable for patch preparation. It
follows the final target, treats a dangling symlink as missing, may truncate by
byte or line budget, and is capped at 1 MiB/100,000 lines while patch/write
bodies may be 4 MiB. Using it would allow a later symlink or large-file failure
to occur only after an earlier mutation, violating all-base-validation before
the first mutation.

Task 6 therefore adds a private static `PATCH_SNAPSHOT_SCRIPT` used only by
`patch.rs`. Rust splits each already-resolved non-root target into parent and
basename before rendering the fixed command. For each target, the script:

1. validates exactly three arguments: parent, basename, and bounded decimal
   byte budget;
2. follow-stats and enters the parent with the same pre/post-`cd`
   device/inode binding and inaccessible-ancestor classifier as Task 5;
3. thereafter addresses only `./<basename>`;
4. reports `Missing` only when the bound parent exists and neither a final
   entry nor a dangling final symlink exists;
5. lstat-classifies the final entry without following it;
6. accepts only a regular non-symlink with no special permission bits;
7. captures device, inode, mode, size, and link count;
8. rejects a file whose size exceeds the remaining aggregate budget before
   emitting content;
9. hashes through Task 5's probed no-follow input form;
10. streams the complete bytes once to the private local spool through a
   no-follow input form, with no line limit or truncation mode;
11. repeats lstat and no-follow SHA-256; and
12. returns success only when identity, type, mode, size, link count, both
    remote hashes, and the locally computed hash of streamed bytes agree.

Intermediate parent symlinks remain allowed, consistent with Task 5 and the
approved operational-guard threat model. Only the final entry is no-follow.
Live symlinks, dangling symlinks, directories, FIFOs, devices, sockets, and
special-mode regular files are `WriteConflict` for patch preparation.

The snapshot uses `FixedOperationKind::ReadOnly`, private spools, the existing
read-only fixed wrapper, and existing probed capabilities including the
Task 5 no-follow input behavior. It never invokes a mutation script. A file
changing during transfer is `ReadConflict`; permission and parent errors retain
their existing typed codes. All snapshot spools are released before mutation
except the owned in-memory base bytes.

Create targets are also snapshotted. `Missing` means no directory entry,
including no dangling symlink, under an existing bound parent. A missing
parent is `NotFound`, a non-directory parent is `NotDirectory`, and a
deterministically inaccessible ancestor is `PermissionDenied`, all before any
mutation. An existing empty regular file is not missing and therefore
conflicts with Create.

Snapshots occur sequentially in patch order before any local output is
committed remotely. A later external race remains possible; expected-hash
Replace, no-clobber Create, and guarded delete close it at each mutation.

## 8. Resource Limits

The following compiled ceilings are binding:

```rust
const MAX_PATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_PATCH_FILES: usize = 32;
const MAX_PATCH_HUNKS: usize = 4_096;
const MAX_PATCH_BODY_LINES: usize = 100_000;
const MAX_PATCH_PATH_BYTES: usize = 64 * 1024;
```

`parse_patch` enforces the compiled ceilings that do not depend on a host.
`RemoteBridge::apply_patch` additionally enforces:

- `patch.len() <= effective_limits.max_write_bytes`;
- total complete base bytes across regular targets
  `<= effective_limits.max_write_bytes`;
- every single output and total write-output bytes
  `<= effective_limits.max_write_bytes`; and
- every rendered snapshot/write/delete fixed request fits
  `effective_limits.max_frame_bytes`.

Delete output contributes zero bytes; its downloaded base still contributes to
the base budget. Create contributes zero base bytes and its complete new bytes
to the output budget. All counters and range calculations use checked
arithmetic. Limit failures are `RequestTooLarge` and occur before the first
mutation.

These bounds cap simultaneous patch text, base bytes, output bytes, line
objects, and hunk objects. They deliberately do not reuse the public
`max_read_bytes` ceiling because that 1 MiB Agent-facing pagination limit is
not a safe complete-base limit for a 4 MiB mutation operation.

## 9. Error and Progress Model

Task 6 extends `ErrorDetails` with omitted-when-absent fields:

```rust
pub failed_path: Option<String>,
pub changed_paths: Option<Vec<String>>,
pub not_changed_paths: Option<Vec<String>>,
pub outcome_unknown_paths: Option<Vec<String>>,
```

These fields are added only after a patch has parsed successfully and a path
set is known. The underlying `ErrorCode`, message, retryability, host, elapsed
information, and `mutation_may_have_applied` remain authoritative. Task 6 does
not replace a Task 5 error with a generic patch error.

The lists mean:

- `changed_paths`: mutation success was positively confirmed;
- `not_changed_paths`: this patch operation did not start a mutation for the
  path, or Task 5 returned a closed domain result proving no target commit;
- `outcome_unknown_paths`: a mutation child may have started but its target
  result was not confirmed.

They preserve patch order, contain no duplicates, and partition every parsed
path. `outcome_unknown_paths` is empty or contains only the currently failing
path because execution stops immediately. “Not changed” means not changed by
this bridge invocation; it does not claim that another remote process left the
path unchanged.

Progress classification is:

| Failure point | Changed | Not changed | Unknown |
|---|---|---|---|
| Snapshot or local application | none | all paths | none |
| Before mutation `i` starts | confirmed prefix | `i` and suffix | none |
| Closed domain failure for `i` | confirmed prefix | `i` and suffix | none |
| Ambiguous outcome for `i` | confirmed prefix | suffix after `i` | `i` |

An unknown outcome is never retried and is never followed by a later patch
mutation or a speculative read intended to reclassify it. Task 5 requires a
new caller-directed inspection before deciding what occurred.

## 10. Cancellation Semantics

One caller `CancellationToken` is cloned into every snapshot and mutation.
Cancellation follows the same phase boundary as Task 5:

- Before or during local parse/application: return `Cancelled` at the next
  explicit check; no mutation has occurred.
- During snapshot: the read-only fixed child returns `Cancelled`; all paths are
  reported not changed.
- After preparation but before mutation `i`: return `Cancelled` with the
  confirmed prefix changed and `i` plus the suffix not changed.
- Before Task 5's mutation child spawns: preserve `Cancelled` with no mutation
  flag; the current path is not changed.
- After a mutation child may have spawned: preserve
  `MutationOutcomeUnknown`, `mutation_may_have_applied=true`, and place only the
  current path in `outcome_unknown_paths`.
- After the final mutation has returned confirmed success, a later token edge
  does not turn that completed result into cancellation.

The orchestrator checks cancellation before each snapshot, after all local
application, and before each mutation. It records a successful mutation
synchronously before the next await point, so a confirmed result cannot be
lost to a cancellation race.

## 11. Mutation Mapping and Result Semantics

Prepared mutations retain patch order and exact snapshot hashes:

| Patch operation | Task 5 call |
|---|---|
| Create | `write` with UTF-8 content and `WriteMode::Create` |
| Update | `write` with UTF-8 content and `WriteMode::Replace { expected_sha256: Some(base_hash) }` |
| Delete | `guarded_delete` with the mandatory base hash |

Create mode is Task 5's fixed 0600. Update preserves the target's ordinary
mode through Task 5. The restricted grammar accepts no mode metadata.

On complete success, `ApplyPatchResult.changed_paths` contains every patch
path exactly once in patch order. Its flattened context is retained from the
first successful base snapshot, including when every eventual mutation is a
delete; every later snapshot must report the same host and physical root. On
failure, no `ApplyPatchResult` is returned; progress is attached to the
original `BridgeError`.

## 12. TDD and Acceptance Requirements

Implementation is strict red-green-refactor. Parser tests precede parser code;
application tests precede application code; no-follow snapshot tests precede
snapshot code; orchestration and partial-failure tests precede the public
method.

Acceptance requires tests for:

- multi-file and multi-hunk updates;
- create, update-to-empty, and delete of nonempty text;
- exact no-newline behavior on old, new, and context lines;
- malformed, overflowing, inconsistent, and overlapping ranges;
- absolute, traversal, noncanonical, mismatched, and duplicate paths;
- Git metadata, rename, mode, and binary rejection;
- stable-base mismatch and changing-during-read conflict;
- live and dangling final symlink rejection before mutation;
- complete bases above the public 1 MiB read ceiling but within the 4 MiB
  patch ceiling;
- all bases and all outputs validated before the first mutation;
- exact partial progress when the second mutation has a definite failure;
- exact `outcome_unknown_paths` when the second mutation is ambiguous;
- cancellation during snapshot, between mutations, before mutation spawn, and
  after mutation spawn;
- no mutation retry and no later mutation after failure; and
- zero SSH processes for malformed/traversal/binary/read-only local rejection.

The Task 6 gate is:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test remote_ops -- --nocapture
cargo test --all-targets
git diff --check
```

No test may mutate a real remote host. Fake SSH and temporary local directories
remain the Task 6 integration boundary.
