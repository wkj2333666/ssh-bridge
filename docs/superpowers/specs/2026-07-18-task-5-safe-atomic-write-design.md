# Task 5 Safe Atomic Remote Writes and Guarded Delete Design

Date: 2026-07-18

Status: Controller bindings and independent-review revisions incorporated

## 1. Authority and Scope

This design implements Task 5 from the approved Rust bridge design and plan.
The binding decisions in `.superpowers/sdd/task-5-clarifications.md` are part
of this design and take precedence if the documents ever differ.

Task 5 adds:

- public complete-file create and replace through `RemoteBridge::write`;
- one-shot mutation execution through the existing fixed-script SSH runner;
- production-shaped `safe_write` and `guarded_delete` capability probes;
- a crate-private expected-hash guarded delete for Task 6;
- stable unknown-mutation error reporting; and
- adversarial tests for symlinks, races, cancellation, disconnects, cleanup,
  exact permissions, and shell metacharacters.

Task 5 does not add patch parsing/application, MCP schemas or dispatch, CLI
commands, SSHFS behavior, or a Python runtime. It does not create remote parent
directories. It does not claim confinement against symlinks or a malicious
process running as the same remote account.

## 2. Security and Execution Invariants

Every mutation obeys these invariants:

1. Host lookup, read-only enforcement, path validation, content decoding,
   byte limits, expected-hash validation, local content hashing, and exact
   rendered-command-plus-stdin bounds complete before `ssh -G` or any remote
   process launch.
2. An API call starts at most one fixed mutation child. An uncached `ssh -G`
   and capability probe may precede it, but no mutation error causes an
   automatic retry or same-call reprobe.
3. The mutation program is a compile-time static POSIX shell script. Caller
   values are quoted positional parameters through the sole `shell_word`
   encoder. File content is raw SSH stdin and never shell source or a command
   argument.
4. A cheap production-shaped sentinel runs before the script reads caller
   stdin or touches the caller's parent or target. A genuine semantic mismatch
   may return only the strict capability-mismatch record for that operation.
5. Staging uses an unpredictable same-directory `mktemp` file, `umask 077`,
   mode `0600`, GNU `dd` no-follow output, and a cleanup trap. The script
   verifies type, non-symlink status, effective-UID ownership, mode, size,
   SHA-256, parent device, and link count before installation.
6. Create installs with a same-filesystem hard link and cannot replace an
   existing directory entry. Replace installs content with same-directory
   `mv -T`, then safely finalizes and verifies the preserved ordinary mode.
7. A successful result is returned only after the temporary pathname is
   confirmed absent and the installed target's complete content and metadata
   are verified.
8. Once a mutation child may have executed, any outcome not proven by one
   strict closed result is `MUTATION_OUTCOME_UNKNOWN`, non-retryable, and
   marked `mutation_may_have_applied=true`.
9. The bridge owns at most one decoded mutation-content buffer of
   `max_write_bytes` per in-flight call, apart from the API source string and
   small protocol/command buffers. The decoded `Vec<u8>` is moved into runner
   stdin and is never cloned; Base64 source is released as soon as the
   resolved request no longer needs it.

The remote account's permissions remain the hard boundary. Configured roots
and intermediate parent symlinks are allowed, as in the approved operational-
guard threat model. The final target symlink is never followed by write or
delete logic.

## 3. Public and Crate-Private API

The public request API is:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    pub host: String,
    pub path: String,
    pub content: String,
    pub encoding: WriteEncoding,
    pub mode: WriteMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteEncoding {
    Utf8,
    Base64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteMode {
    Create,
    Replace { expected_sha256: Option<String> },
}

impl RemoteBridge {
    pub async fn write(
        &self,
        request: WriteRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<WriteResult>;
}
```

UTF-8 content is the exact byte sequence of the Rust string and may be empty
or contain NUL. Base64 is RFC 4648 standard padded canonical data. The base64
0.22 standard engine is used with required canonical padding and trailing bits
disallowed, which is equivalent to decode-then-re-encode equality without a
second full encoded allocation. Whitespace, URL-safe alphabet, missing padding,
and noncanonical trailing bits are rejected. The empty string is the canonical
Base64 encoding of an empty byte sequence.

The exact public result contract is:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteOperation {
    Create,
    Replace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteResult {
    #[serde(flatten)]
    pub context: RemoteContext,
    pub actual_path: EncodedValue,
    pub relative_path: EncodedValue,
    pub operation: WriteOperation,
    pub raw_bytes: u64,
    pub sha256: String,
    pub mode: u32,
    pub temporary_cleanup_confirmed: bool,
}
```

`temporary_cleanup_confirmed` is present and true in every successful result.
No failed or unknown operation returns a `WriteResult`. No result contains a
temporary pathname or remote diagnostic text.

Task 5 also adds a crate-private interface for later patch orchestration:

```rust
pub(crate) struct GuardedDeleteRequest {
    pub host: String,
    pub path: String,
    pub expected_sha256: String,
}

pub(crate) struct GuardedDeleteResult {
    pub actual_path: EncodedValue,
    pub relative_path: EncodedValue,
    pub deleted_sha256: String,
    pub absence_confirmed: bool,
}

impl RemoteBridge {
    pub(crate) async fn guarded_delete(
        &self,
        request: GuardedDeleteRequest,
        cancel: CancellationToken,
    ) -> BridgeResult<GuardedDeleteResult>;
}
```

The delete types do not derive `Serialize` and are not public MCP surface.
Task 6 may call this operation but may not weaken or bypass its validation.

## 4. Local Validation and Resolution

`RemoteBridge::write` resolves the request completely before the runner is
called:

1. Resolve the exact host alias through `Config::host`.
2. Reject a read-only profile with `ReadOnlyHost`.
3. Reject an empty path, `.`, embedded NUL, or more than 64 KiB of UTF-8 path
   data.
4. Resolve the path lexically beneath the configured root. Reject traversal,
   an empty relative path, or a path resolving to the configured root.
5. Split the normalized absolute path into an absolute parent and a nonempty
   basename. Only these two values cross the shell boundary.
6. Decode content exactly and reject decoded length above the host's effective
   `max_write_bytes`.
7. Validate that an expected hash appears only in `Replace`, and is exactly 64
   lowercase hexadecimal characters without a prefix.
8. Compute the raw byte count and lowercase SHA-256 locally.
9. Build the exact fixed command using the static script and positional
   arguments, then checked-add raw stdin length. Reject a sum above the host's
   effective `max_frame_bytes` before any process launch.

The rendered-frame check is performed on the final shell-word-quoted command,
not an estimate. Repeated single quotes in a legal pathname may expand
substantially under `shell_word`; that expansion and stdin bytes are both
included in the zero-launch bound.

Empty decoded content is valid. Limits and hashes count decoded raw bytes, not
Base64 source length. All arithmetic is checked. Delete performs the same host,
read-only, path, root, and rendered-frame validation and requires a valid
expected hash.

The resolved write arguments are parent, basename, operation, content byte
count, content SHA-256, an explicit expected-hash-present flag, and the expected
hash value. No untrusted value is interpolated into script text. Once these
arguments and the final command are built, the source request is dropped and
the sole decoded buffer is moved as raw stdin. The script rejects an internally
inconsistent positional shape with a nonzero exit; after a mutation child has
launched this is reported as unknown outcome.

## 5. One-Shot Fixed Mutation Runner

The existing fixed runner already renders:

```text
exec sh -c <quoted-static-script> codex-ssh-bridge-op <quoted-arguments...>
```

Task 5 makes the one-attempt boundary explicit as
`SshRunner::execute_fixed_once`. Task 4's read-only wrapper calls it and retains
its own sole optional retry after a strict read-only mismatch. Write and delete
call `execute_fixed_once` directly exactly once and never call
`execute_readonly_fixed`.

`FixedRunRequest` gains an internal operation kind. Read-only requests retain
current behavior. Mutation requests use a mutation child phase so the runner
can distinguish validation/resolve/probe failures from failures after a child
has spawned:

- local validation, queue cancellation, `ssh -G`, probe, and cached-false
  capability failures keep their existing errors and do not set
  `mutation_may_have_applied`;
- after successful mutation-child spawn, cancellation, timeout, output limit,
  I/O/capture failure, signal exit, status 255, disconnect, or any nonzero
  status becomes `MutationOutcomeUnknown`;
- exit zero yields a private spooled `FixedRunResult`; the facade must still
  parse one strict result before it can claim success or a domain error.

This phase is recorded by control flow, not inferred from stderr. Mutation
errors are never marked retryable.

Internal stdout and stderr are forced to private local mode-0600 spools under
an `InternalSpoolOwner`. The owner lives from facade entry through result
parsing. Drop/abort cleanup remains the normal local spool lifecycle.

## 6. Capability Probe and Stale-Capability Sentinel

The capability protocol adds two booleans:

- `safe_write`
- `guarded_delete`

Both are production-shaped functional probes inside the capability probe's
private tree. Mere command availability is insufficient.

The `safe_write` probe executes and verifies the complete production forms for:

- the shared exact same-directory `mktemp --tmpdir="$dir"
  .codex-ssh-bridge.XXXXXXXXXX` helper and mode 0600 under `umask 077`;
- the shared exact dereferencing parent-stat helper, GNU
  `stat -L --printf='%f:%u:%a:%s:%d:%i:%h\n' -- "$path"`, alongside the
  no-follow final-entry lstat helper;
- `id -u` and GNU `stat --printf` fields for type, UID, mode, size, device,
  inode, and link count;
- GNU `dd` with `bs=262144 status=none conv=notrunc oflag=nofollow`, including rejection
  of a symlink output operand without modifying its referent;
- GNU `dd` with `bs=262144 status=none iflag=nofollow` as the input side of the exact
  target-hash helper, including a separately captured producer status so a
  failed no-follow open cannot be mistaken for the empty-file digest;
- `sha256sum --` with exact lowercase digest extraction;
- `ln --` hard-link installation and collision no-clobber behavior;
- `mv -T --` same-directory replacement;
- GNU `chmod -h <mode> -- <operand>` on a regular file;
- successful `chmod -h` on a symlink operand without changing the referent's
  mode or content; and
- cleanup after both successful and failed probe paths.

The `guarded_delete` probe verifies the exact lstat/type/hash/recheck, a second
complete hash immediately before the exact `rm -f --` form, successful absence
confirmation, symlink rejection before unlink, and cleanup. Each flag is
independently false when its exact behavior is unavailable.

Each real mutation begins with a smaller exact sentinel for its own static
required key. The sentinel uses only a separate private scratch tree. It
completes before caller stdin is read and before the caller parent or target is
touched. It distinguishes semantic mismatch from setup/I/O failure:

- semantic mismatch emits the sole closed capability-mismatch result, exits
  zero, invalidates the cache for a future independent request, and returns
  `RemoteCapabilityMissing` without retrying;
- setup/I/O failure is not a capability mismatch and cannot trigger reprobe or
  retry. If it is not represented by an allowed closed result after the
  mutation child has spawned, the caller receives unknown outcome.

The sentinel, full probe, and caller-data path invoke textually identical
compact functions for parent-follow stat, final-entry lstat, same-directory
mktemp, no-follow `dd` input/output, hash, hard link, rename, chmod, and remove.
Stateful PATH-shim tests pass the full probe and then corrupt each real command
form in turn. The real sentinel must detect that change before reading caller
stdin or statting/entering the caller parent, run only one mutation child, make
no same-call retry, invalidate the cache, and permit only a later independent
call to reprobe.

The stat parser rejects the whole line before field splitting unless it is a
nonempty member of the closed numeric/colon character set, so pathname
expansion cannot occur during a POSIX split. The hash helper runs in a subshell
with one cleanup/return path: every malformed, duplicate-status, or utility-
failure path restores `IFS` and cannot poison a later successful hash.

## 7. Closed Mutation Result Protocol

Expected results use remote exit status zero, stdout only, strict NUL-delimited
ASCII fields, and empty stderr. The allowed record shapes are frozen below.

Write success:

```text
STATUS=SUCCESS\0OPERATION=CREATE|REPLACE\0SIZE=<decimal>\0SHA256=<64-lower-hex>\0MODE=<decimal>\0TEMPORARY_CLEANUP_CONFIRMED=1\0
```

Delete success:

```text
STATUS=SUCCESS\0OPERATION=DELETE\0SHA256=<64-lower-hex>\0ABSENCE_CONFIRMED=1\0
```

Domain errors have exactly one field:

```text
STATUS=WRITE_CONFLICT\0
STATUS=NOT_FOUND\0
STATUS=NOT_DIRECTORY\0
STATUS=PERMISSION_DENIED\0
```

Capability mismatch has exactly two fields and is allowed only before caller
stdin or caller-target access:

```text
STATUS=CAPABILITY_MISMATCH\0CAPABILITY=safe_write|guarded_delete\0
```

The parser requires a terminal NUL, the exact field order and count, no empty
or duplicate fields, empty stderr, known enum values, checked integers, the
request's operation/size/hash, and a final mode at most 0777. Remote paths and
diagnostics never appear in protocol output.

`MODE` is decimal protocol text derived from a validated GNU `stat %a` octal
field. Thus mode 0600 is emitted as `384` and 0640 as `416`; the Rust parser
does not interpret the protocol field as octal text.

An internally malformed, unknown, duplicate, extra, or trailing record is a
`ProtocolError` at the parser boundary. Because the mutation child has already
run, the public facade converts that parser failure to
`MutationOutcomeUnknown`; it never exposes a false protocol-only retry path.

Before emitting any domain result after staging begins, the script must clean
the temporary pathname and confirm that neither an existing nor dangling entry
remains there. Cleanup failure produces no closed result and therefore becomes
unknown outcome. Success records are emitted only after the same confirmation.

## 8. Static Safe-Write Protocol

The write script performs these phases in one child.

### 8.1 Sentinel and parent entry

1. Initialize `tmp` to empty and install cleanup and signal traps.
2. Run the `safe_write` sentinel in private scratch.
3. Validate the positional protocol without copying caller data to output.
4. Classify the parent with the shared exact `parent_stat_follow` helper:
   absent/dangling is `NotFound` and an existing non-directory is
   `NotDirectory`. Record the dereferenced directory's device and inode before
   entry. This deliberately permits a configured-root or intermediate parent
   symlink.
5. Use POSIX `cd "$parent"` (the parent is an already validated absolute
   pathname). If it fails, re-stat the parent: return `PermissionDenied` only
   when it is still provably the same existing directory and remains
   unenterable. A missing, replaced, type-raced, or otherwise unproved failure
   emits no typed record and is therefore unknown outcome. After successful
   entry, but before reading stdin or creating a temporary file, follow-stat
   `.` with the same exact helper and require its device/inode to equal the
   pre-entry identity. A mismatch emits no typed record and is therefore
   unknown. After this binding every caller target operand is
   `./$basename`; the script never reconstructs or evaluates shell source.

The configured root and intermediate symlinks may be followed while entering
the parent. The final `./$basename` is always inspected with lstat/no-follow
semantics before any operation that could follow it.

### 8.2 Initial target guard

Create rejects any existing directory entry, including a dangling symlink, as
`WriteConflict`. The final hard-link operation remains authoritative if an
entry appears later.

Replace requires an existing regular non-symlink. Missing is `NotFound`; a
directory, special file, live symlink, or dangling symlink is `WriteConflict`.
It captures device, inode, ordinary mode, and full mode. Any setuid, setgid, or
sticky bit is `WriteConflict`. The ordinary low 0777 bits become the intended
final mode. Target ownership is intentionally not restricted.

If an expected hash exists, an early comparison may reject obvious stale
input, but it does not replace the mandatory final comparison.

Every target hash uses the probed no-follow hash helper: GNU `dd` opens the
target with `iflag=nofollow` and streams bytes to `sha256sum`, while the static
wrapper captures and validates the `dd` status separately from the digest.
The helper suppresses diagnostics and fails if either process fails. It never
uses `sha256sum <path>` because that pathname open would follow a symlink raced
into the final target position.

### 8.3 Stage and verify

The script sets `umask 077` and creates a same-directory pathname with the
production `mktemp` form. It streams stdin with the probed no-follow `dd` form.
Before install, it verifies all of the following from closed `stat`, `id`, and
hash output. The stat helper emits one strict numeric ASCII line with a fixed
colon-separated field count (`type:uid:mode:size:device:inode:nlink`). Shell
variables never store NUL: every field's numeric character set and range are
validated before use, and NUL remains reserved for the bridge result protocol.

- regular file and not a symlink;
- owner equals the effective UID;
- mode is exactly 0600;
- size equals Rust's decoded byte count;
- SHA-256 equals Rust's content hash;
- device equals the current parent directory's device; and
- link count equals one.

Any failed safety invariant produces no success. The script repeats size/hash
and relevant metadata verification after any staging metadata operation that
could affect safety.

### 8.4 Create commit

Create calls `ln -- "$tmp" "$target"`. A collision, including a target created
during upload, is `WriteConflict`. Other unproven link failures do not produce
a false domain result.

After a successful link, the script verifies that target and staging names are
the same regular inode, target mode is 0600, size/hash are exact, and the link
count reflects the two names. It then unlinks only the staging pathname,
confirms that pathname is absent, and re-verifies the installed target with
link count one. Only then does it emit successful Create with final mode 0600.

### 8.5 Replace commit and permission finalization

Immediately before rename, Replace re-lstats the target and rejects a missing,
symlink, non-regular, special-mode, device/inode, or ordinary-mode race as
`WriteConflict` when the change is provable. With an expected hash, it computes
the complete target SHA-256 immediately before rename and then rechecks target
identity/type/mode so a hash-time replacement is also detected.

The script captures the verified staging device/inode, then calls
`mv -T -- "$tmp" "$target"`. The rename atomically installs the new content in
the same directory and removes the staging pathname. The installed file is
still mode 0600.

The script verifies that the target is the staged regular inode, owned by the
effective UID, mode 0600, with exact size/hash. This is the final content open:
the verified staged inode's size and complete SHA-256 are frozen before chmod.
It then calls the functionally
probed exact GNU form:

```text
chmod -h <preserved-ordinary-mode> -- ./<basename>
```

`-h/--no-dereference` prevents a raced symlink operand from changing its
referent. After chmod, the script does not reopen the installed content: modes
0000 and 0200 must succeed without requiring read access. It lstat-verifies
target type, non-symlink status, staged device/inode, owner, exact preserved
mode, the already-frozen size, link count one, and absent staging pathname.
Only then does it emit successful Replace.

The content rename is atomic, but permission finalization is deliberately
post-rename so a group/other-writable staging name is never exposed. A failure
from rename through final chmod verification is an unknown mutation outcome.

## 9. Cleanup and Signal Handling

The script does not use the brief's ambiguous combined one-line trap. It uses
POSIX trap syntax and separate semantics:

- `tmp` starts empty;
- trap 0 removes only a nonempty controlled `mktemp` pathname;
- HUP, INT, and TERM handlers run cleanup and terminate nonzero;
- typed-error helpers clean, confirm absence, use `trap - 0 HUP INT TERM` to
  disable traps as appropriate,
  and only then emit their closed record; and
- successful link/rename clears `tmp` only after the old staging pathname is
  proven absent.

Cleanup uses the controlled same-directory temporary name and never a caller-
provided cleanup path. The script does not claim cleanup after disconnect or
an unconfirmed signal path. Local internal spool cleanup remains independently
owned by `InternalSpoolOwner`.

## 10. Guarded Delete Protocol

Guarded delete is one fixed mutation child and never invokes read or stat as a
separate SSH operation.

1. Complete all local host/read-only/path/hash/frame validation.
2. Run the `guarded_delete` sentinel before caller-parent access.
3. Bind and enter the existing parent using the same exact follow-stat helper
   and pre/post-`cd` device/inode equality check as write, then use only
   `./$basename`.
4. Return `NotFound` for no directory entry. Reject a symlink, directory, or
   special file as `WriteConflict`.
5. Capture the regular target's device and inode without following symlinks.
6. Hash the complete file with the no-follow `dd` input helper and require the
   mandatory expected digest.
7. Immediately before `rm -f --`, repeat the lstat/type/identity guard and the
   complete expected-hash comparison.
8. Unlink the target and confirm that neither an existing nor dangling entry
   remains.
9. Emit Delete success with the expected deleted hash and
   `ABSENCE_CONFIRMED=1`.

Missing is never idempotent success. A pre-unlink hash/type/symlink/identity
race is `WriteConflict`. An error or unexpected entry after unlink may mean the
expected directory entry was removed, so it is unknown outcome rather than a
false conflict or success.

Shell utilities cannot provide a perfect compare-and-unlink against a
malicious same-account process. The final hash/type/identity checks minimize
the window, while the approved trust model treats that process as sharing the
SSH security boundary.

## 11. Error Model

Task 5 adds:

```rust
ErrorCode::MutationOutcomeUnknown
ErrorDetails {
    mutation_may_have_applied: Option<bool>,
    // existing fields remain unchanged
}
```

The serialized code is `MUTATION_OUTCOME_UNKNOWN`. Its message is fixed,
contains no remote data, and `retryable=false`.

Error grouping is:

| Condition | Error |
|---|---|
| read-only profile | `ReadOnlyHost` |
| invalid encoding/hash/range/empty target | `InvalidArgument` |
| decoded or rendered frame too large | `RequestTooLarge` |
| lexical escape | `PathOutsideRoot` |
| cached false or strict stale sentinel | `RemoteCapabilityMissing` |
| missing parent/required replace/delete target | `NotFound` |
| non-directory parent | `NotDirectory` |
| deterministic parent permission failure | `PermissionDenied` |
| create collision, wrong target type, expected hash, identity/mode race | `WriteConflict` |
| any unclosed outcome after mutation-child spawn | `MutationOutcomeUnknown` |

`MutationOutcomeUnknown` never includes changed status, cleanup confirmation,
or a write/delete result. It may include existing safe host/elapsed/exit fields
plus `mutation_may_have_applied=true`, but never remote stderr or a temporary
path. Callers must inspect the target with a new read before deciding what to
do; the bridge does not retry automatically.

Every successful write context reports the fixed interpreter truthfully as
POSIX sh (`RemoteContext.shell.kind = sh`, no version, no fallback). Bash-to-sh
fallback visibility belongs to the separate arbitrary `remote_run` path; Task
5 neither changes nor regresses that Agent-visible behavior.

## 12. Test Strategy

Implementation follows red-green-refactor. Tests are deterministic and use no
Python.

### 12.1 Local validation and API shape

- exact request/result serde shape and lowercase operations;
- canonical UTF-8/Base64 decoding, empty and NUL-bearing content;
- invalid Base64, expected hashes, target roots, traversal, NUL, and 64-KiB
  paths launch zero processes;
- decoded `max_write_bytes` and exact final rendered command plus stdin frame
  bound, including a quote-amplifying path containing many single quotes;
- read-only rejection before `ssh -G`; and
- Rust/remote raw byte count and SHA-256 agreement;
- MODE decimal conversions 0600 to 384 and 0640 to 416; and
- five concurrent hosts each writing 4 MiB, one child and one staging file per
  call, complete cleanup, and a controlled baseline/delta memory observation
  with a deliberately broad upper bound. The test records Base64's API-source
  transient separately and avoids a brittle absolute-RSS assertion.

### 12.2 Functional capabilities and retry boundary

- full probe flags exact parent-follow stat/final lstat/mktemp/dd/stat/id/hash/
  chmod/ln/mv/rm forms;
- fine-grained PATH shims make only the affected flag false;
- malformed and duplicate hash-status output fails closed without poisoning a
  subsequent normal hash invocation;
- `chmod -h` changes a regular file exactly, succeeds on a symlink operand,
  and never changes the symlink referent's mode or content;
- probe and sentinel scratch cleanup on success and failure;
- cached false launches no mutation child;
- one stale pre-mutation sentinel invalidates for a future request but the
  current request executes no second probe or mutation child; and
- setup, transport, cancellation, protocol, status 255, and disconnect never
  retry.

### 12.3 Create and replace adversarial cases

- reproduce the prototype temp-name symlink attack deterministically by
  replacing the staging pathname before the real no-follow `dd`; the outside
  sentinel must remain unchanged;
- file, directory, live symlink, and dangling-symlink create collisions;
- target created during upload is a hard-link no-clobber conflict;
- same-directory install and no residual `.codex-ssh-bridge.*` pathname;
- create final mode 0600;
- replace preserves ordinary 0000 through 0777 modes and rejects setuid,
  setgid, and sticky targets;
- modes 0000 and 0200 succeed because post-chmod verification never reopens
  content;
- a symlink parent is allowed, but replacing the followed parent between its
  pre-entry stat and the post-`cd` stat of `.` fails before stdin/temp work;
- replace missing, wrong type, dangling/live symlink, expected-hash mismatch,
  inode race, mode race, and hash race;
- hostile target containing quotes, whitespace, newline, leading hyphen,
  wildcard text, dollar, backtick, command-substitution text, and Unicode;
- staging owner, mode, size, hash, device, and link-count guards;
- cancellation/signal/interrupted stdin cleanup; and
- local internal spool cleanup after future abort.

### 12.4 Unknown outcomes

- fake disconnect after commit returns unknown and starts exactly one mutation
  child;
- malformed success output after commit returns unknown;
- nonempty stderr, output cap, timeout, cancellation after spawn, and status
  255 return unknown without retry;
- chmod failure after successful rename returns unknown, never false success;
- final mode/hash/type verification failure returns unknown; and
- unknown errors expose the fixed code/flag but no remote diagnostic, target
  changed status, or cleanup claim.

### 12.5 Guarded delete

Crate-local tests cover mandatory valid expected hash, success and confirmed
absence, missing non-idempotence, wrong hash, directory/special/symlink targets,
identity/hash races, read-only and local-validation zero launch, signal/error
behavior, exact one child, no retry, and unknown outcome after a possible
unlink. Task 5 does not add patch tests or a public delete endpoint.

The Task 5 verification gate is:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test remote_ops -- --nocapture
cargo test --test ssh_transport -- --nocapture
cargo test --all-targets
```
