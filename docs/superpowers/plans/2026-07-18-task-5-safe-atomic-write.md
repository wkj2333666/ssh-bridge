# Task 5 Safe Atomic Remote Writes and Guarded Delete Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one-shot, symlink-safe complete-file create/replace and an internal expected-hash guarded delete without automatic mutation retry.

**Architecture:** `RemoteBridge` performs every local validation before launch, then sends raw decoded bytes to one compile-time fixed POSIX script through `SshRunner::execute_fixed_once`. Production-shaped capability probes and pre-mutation sentinels guard exact GNU utility behavior; strict exit-zero NUL records are the only proof of success or a typed domain error, and every ambiguous post-launch outcome becomes `MUTATION_OUTCOME_UNKNOWN`.

**Tech Stack:** Rust 1.91.1, Tokio, tokio-util cancellation, Serde, base64 0.22, sha2 0.10, system OpenSSH, POSIX sh, GNU coreutils, shell fake-SSH fixtures; no Python.

## Global Constraints

- Work only in `/home/wkj/projects/codex-ssh-bridge/.worktrees/rust-ssh-bridge` on `feature/rust-ssh-bridge`, baseline `1639d0c`.
- `.superpowers/sdd/task-5-clarifications.md` is binding and overrides older general capability-reprobe language.
- The runtime, tests, fixtures, and validation commands must not use Python.
- Do not implement Task 6 patch parsing/application, MCP schemas/dispatch, CLI, SSHFS, or packaging.
- Preserve unrelated `ssh_bridge/__pycache__/` and `tests/__pycache__/` exactly as found.
- Follow RED-GREEN-REFACTOR. Before code execution, invoke `superpowers:test-driven-development`; on any unexpected failure, invoke `superpowers:systematic-debugging`; before completion, invoke `superpowers:verification-before-completion`.
- No mutation API call may start more than one fixed mutation child. Mutation never uses `RemoteBridge::execute_readonly_fixed` and never automatically retries or reprobes.
- All host/read-only/path/encoding/size/hash/rendered-frame validation completes before `ssh -G`.
- Remote scripts are compile-time static, caller values are positional arguments, and decoded file bytes are raw stdin.
- Temporary write paths are same-directory, unpredictable, mode 0600, no-follow opened, verified, trapped, and never returned.
- Create is hard-link no-clobber and final mode 0600. Replace is same-directory rename, then probed `chmod -h`, final verification, and preserved ordinary 0777 mode; special bits conflict.
- Replace performs its final installed-inode content size/hash verification while
  the file is still mode 0600. After chmod it does not reopen content; it only
  lstat-checks identity/type/owner/exact mode/frozen size/nlink and temp absence,
  so preserved modes 0000 and 0200 work.
- Full probe, sentinel, and producer share exact `parent_stat_follow`, lstat,
  same-directory mktemp, dd, hash, ln/mv/chmod/rm command forms. A successful
  `cd "$parent"` is bound by a follow-stat of `.` before stdin or staging.
- Each in-flight call owns at most one decoded buffer up to `max_write_bytes`
  apart from its API source and short command/protocol data; the `Vec<u8>` is
  moved to runner stdin without cloning and the source is released promptly.
- Expected domain results are exit zero, one strict NUL stdout record, and empty stderr. Unclosed post-spawn outcomes are non-retryable unknown mutations.
- Guarded delete remains crate-private, requires an expected hash, and is not an MCP/public-delete surface.
- The controller requested one final implementation commit, so intermediate task gates record test evidence but do not commit. The final commit includes spec, plan, code, tests, and `.superpowers/sdd/task-5-report.md`.

---

## File Map

- `src/error.rs`: add the stable unknown-mutation code, detail flag, and fixed constructor.
- `src/capability.rs`: add production-shaped `safe_write` and `guarded_delete` functional probes and records.
- `src/ssh/process.rs`: make the single-attempt fixed boundary explicit and classify post-spawn mutation ambiguity.
- `src/ssh/mod.rs`: re-export the renamed crate-private fixed runner types/functions if needed.
- `src/remote/mod.rs`: expose write request/result types, register `write`, and keep guarded delete crate-private.
- `src/remote/write.rs`: own local write/delete resolution, strict protocol parsing, fixed scripts, one-shot orchestration, and crate-local guarded-delete tests.
- `src/remote/metadata.rs`, `src/remote/read.rs`, `src/remote/search.rs`: set their fixed operation kind and call the renamed one-attempt runner through the existing read-only wrapper; no semantic changes.
- `tests/fixtures/fake-ssh.sh`: advertise new synthetic flags and add deterministic post-commit/disconnect or protocol-corruption fixture controls only where a PATH shim cannot express the case.
- `tests/ssh_transport.rs`: verify exact capability behavior, isolated false flags, cleanup, and mutation phase classification.
- `tests/remote_ops.rs`: verify public API/serde, zero-launch validation, create/replace, attacks, no retry, cleanup, and unknown outcomes.
- `docs/superpowers/specs/2026-07-18-task-5-safe-atomic-write-design.md`: approved Task 5 design.
- `docs/superpowers/plans/2026-07-18-task-5-safe-atomic-write.md`: this execution plan.
- `.superpowers/sdd/task-5-report.md`: final commands, results, safety evidence, commit, and residual limitations.

---

### Task 1: Freeze Errors, API Types, Serde, and Zero-Launch Validation

**Files:**
- Modify: `src/error.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Produces: `ErrorCode::MutationOutcomeUnknown` and `ErrorDetails::mutation_may_have_applied`.
- Produces: `WriteRequest`, `WriteEncoding`, `WriteMode`, `WriteOperation`, and `WriteResult` exactly as frozen in the design.
- Consumes later: Task 4 adds resolution and the public async method only when the final static script exists, so exact rendered-frame validation is never implemented against a temporary script.

- [ ] **Step 1: Add failing API and serde tests**

Extend imports in `tests/remote_ops.rs` and add closed-shape tests covering both request modes and exact success/error JSON:

```rust
use codex_ssh_bridge::remote::{
    WriteEncoding, WriteMode, WriteOperation, WriteRequest, WriteResult,
};

#[test]
fn task5_write_result_shape_and_unknown_error_are_closed() {
    let result = WriteResult {
        context: context(),
        actual_path: value("/root/a"),
        relative_path: value("a"),
        operation: WriteOperation::Replace,
        raw_bytes: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        mode: 0o640,
        temporary_cleanup_confirmed: true,
    };
    assert_eq!(serde_json::to_value(result).unwrap()["operation"], "replace");
    let mut error = BridgeError::new(
        ErrorCode::MutationOutcomeUnknown,
        "remote mutation outcome could not be confirmed",
        false,
    );
    error.details.mutation_may_have_applied = Some(true);
    let json = serde_json::to_value(error).unwrap();
    assert_eq!(json["code"], "MUTATION_OUTCOME_UNKNOWN");
    assert_eq!(json["retryable"], false);
    assert_eq!(json["details"]["mutation_may_have_applied"], true);
}
```

- [ ] **Step 2: Run focused tests and verify RED**

Run:

```bash
cargo test --test remote_ops task5_write_result_shape_and_unknown_error_are_closed -- --exact --nocapture
```

Expected: compilation fails because Task 5 request/result types and unknown error do not exist.

- [ ] **Step 3: Add the stable error and exact API data types**

Add the enum variant and detail field in `src/error.rs`:

```rust
MutationOutcomeUnknown,

pub mutation_may_have_applied: Option<bool>,
```

Add a crate-visible fixed constructor:

```rust
pub(crate) fn mutation_outcome_unknown() -> Self {
    let mut error = Self::new(
        ErrorCode::MutationOutcomeUnknown,
        "remote mutation outcome could not be confirmed",
        false,
    );
    error.details.mutation_may_have_applied = Some(true);
    error
}
```

Define only the public structs/enums in `src/remote/mod.rs` with the exact field
names and serde rename rules from the design. Do not register the write module
or add an async stub in this task.

- [ ] **Step 4: Re-run serde and existing read regressions**

Run:

```bash
cargo fmt --check
cargo test --test remote_ops task5_write_result_shape_and_unknown_error_are_closed -- --exact --nocapture
cargo test --test remote_ops task4_request_and_result_shapes_are_closed_and_serializable -- --exact
```

Expected: all selected tests pass and no Task 4 result shape changes.

---

### Task 2: Add Exact Functional Write/Delete Capabilities

**Files:**
- Modify: `src/capability.rs`
- Modify: `tests/fixtures/fake-ssh.sh`
- Modify: `tests/ssh_transport.rs`

**Interfaces:**
- Produces: `Capability.tools["safe_write"]` and `Capability.tools["guarded_delete"]`.
- Consumes: the existing private probe directory, strict NUL capability parser, and independent boolean tool map.
- Guarantees: exact production command forms work inside private scratch and clean up on every path.

- [ ] **Step 1: Add failing full-probe and fine-grained shim tests**

Add tests that execute the real `CAPABILITY_PROBE_SCRIPT` through
`FAKE_SSH_MODE=local-fixed` and assert both new flags true. Add a table-driven
test with one PATH shim per exact behavior:

```rust
struct WriteCapabilityCase {
    tool: &'static str,
    detect: &'static str,
    corrupt: &'static str,
    expected_false: &'static str,
}

let cases = [
    WriteCapabilityCase { tool: "stat", detect: " -L --printf=", corrupt: "reject only parent-follow form", expected_false: "safe_write" },
    WriteCapabilityCase { tool: "mktemp", detect: "codex-probe-safe-write", corrupt: "exit 1", expected_false: "safe_write" },
    WriteCapabilityCase { tool: "dd", detect: "oflag=nofollow", corrupt: "shift; exec /usr/bin/dd \"$@\"", expected_false: "safe_write" },
    WriteCapabilityCase { tool: "dd", detect: "iflag=nofollow", corrupt: "shift; exec /usr/bin/dd \"$@\"", expected_false: "safe_write" },
    WriteCapabilityCase { tool: "chmod", detect: " -h ", corrupt: "exec /usr/bin/chmod --dereference \"$@\"", expected_false: "safe_write" },
    WriteCapabilityCase { tool: "ln", detect: "codex-probe-safe-write", corrupt: "exit 0", expected_false: "safe_write" },
    WriteCapabilityCase { tool: "mv", detect: " -T ", corrupt: "exit 0", expected_false: "safe_write" },
    WriteCapabilityCase { tool: "rm", detect: "codex-probe-guarded-delete", corrupt: "exit 0", expected_false: "guarded_delete" },
];
```

Each shim must delegate every non-targeted invocation to the corresponding
absolute system tool selected by the table (`/usr/bin/mktemp`, `/usr/bin/dd`,
`/usr/bin/chmod`, `/usr/bin/ln`, `/usr/bin/mv`, or `/usr/bin/rm`).
Assert only the named functional flag becomes false and all probe scratch paths
are absent afterward. Include a symlink referent sentinel proving
`chmod -h 0640 -- "$probe_symlink"` succeeds while leaving the referent's mode
and content unchanged.

Cover every exact primitive: parent-follow stat, final lstat, mktemp, dd output,
dd input, stat parser, id, sha256sum, chmod, ln, mv, and rm. A shared hash
failure may close both mutation flags, but every unrelated Task 4 flag remains
true. Guarded-delete capability requires two complete hashes; a stateful dd
shim that fails only the second one must leave `guarded_delete=false`.

- [ ] **Step 2: Run capability tests and verify RED**

Run:

```bash
cargo test --test ssh_transport task5_full_probe_reports_functional_mutation_flags -- --exact --nocapture
cargo test --test ssh_transport task5_write_capability_flags_fail_independently -- --exact --nocapture
```

Expected: assertions fail because the new flags are absent.

- [ ] **Step 3: Implement compact production-shaped probe helpers**

Extend `TOOL_NAMES` and the probe output with `safe_write` and
`guarded_delete`. Inside the existing private `probe_tmp`, define compact shell
helpers shared by probe fixtures and later copied exactly into mutation
sentinels:

```sh
codex_stat() { stat --printf='%f:%u:%a:%s:%d:%i:%h\n' -- "$1" 2>/dev/null; }
codex_parent_stat_follow() { stat -L --printf='%f:%u:%a:%s:%d:%i:%h\n' -- "$1" 2>/dev/null; }
codex_mktemp() { mktemp --tmpdir="$1" .codex-ssh-bridge.XXXXXXXXXX; }
codex_stage() { dd of="$1" bs=262144 status=none conv=notrunc oflag=nofollow; }
codex_hash_nofollow() {
    codex_hash_capture=$(
        {
            {
                dd if="$1" bs=262144 status=none iflag=nofollow
                printf 'CODEX_DD_STATUS=%s\n' "$?" >&2
            } | sha256sum
            printf 'CODEX_SHA_STATUS=%s\n' "$?" >&2
        } 2>&1
    )
    codex_hash_dd=
    codex_hash_sha=
    codex_hash_digest=
    codex_hash_old_ifs=$IFS
    IFS='
'
    for codex_hash_line in $codex_hash_capture; do
        case "$codex_hash_line" in
            CODEX_DD_STATUS=*)
                [ -z "$codex_hash_dd" ] || return 1
                codex_hash_dd=${codex_hash_line#CODEX_DD_STATUS=}
                ;;
            CODEX_SHA_STATUS=*)
                [ -z "$codex_hash_sha" ] || return 1
                codex_hash_sha=${codex_hash_line#CODEX_SHA_STATUS=}
                ;;
            *'  -')
                [ -z "$codex_hash_digest" ] || return 1
                codex_hash_digest=${codex_hash_line%  -}
                ;;
            *) return 1 ;;
        esac
    done
    IFS=$codex_hash_old_ifs
    [ "$codex_hash_dd" = 0 ] && [ "$codex_hash_sha" = 0 ] || return 1
    [ "${#codex_hash_digest}" -eq 64 ] || return 1
    case "$codex_hash_digest" in *[!0-9a-f]*) return 1 ;; esac
}
codex_mode() { chmod -h "$1" -- "$2"; }
codex_link() { ln -T -- "$1" "$2"; }
codex_replace() { mv -T -- "$1" "$2"; }
codex_remove() { rm -f -- "$1"; }
```

The actual probe must reject a stat line outside the closed numeric/colon
character set before splitting, parse exactly seven fields without pathname
expansion, validate every field's character set/range, and never put
NUL-delimited stat output in a shell variable. The hash helper runs in a
subshell with one result path so all malformed/duplicate status and utility
failure paths restore `IFS`; a later normal hash must still pass. It parses
producer status separately from the digest and verifies regular/symlink
operands, followed symlink parents, owner/mode/size/device/inode/link counts,
content hashes, hard-link collision, rename replacement, regular-file chmod,
symlink referent non-follow with successful symlink chmod status, guarded
regular deletion with an immediately-pre-rm second hash, symlink preguard, and
cleanup.
Set each flag to one only after the complete corresponding fixture passes.

- [ ] **Step 4: Update synthetic fake capability records**

In `tests/fixtures/fake-ssh.sh`, add:

```sh
printf 'TOOL_safe_write=%s\0' "${FAKE_SSH_HAS_SAFE_WRITE:-1}"
printf 'TOOL_guarded_delete=%s\0' "${FAKE_SSH_HAS_GUARDED_DELETE:-1}"
```

Do not synthesize these values in `local-fixed`; that mode continues to execute
the real capability script.

- [ ] **Step 5: Verify capabilities and all existing probe behavior**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test ssh_transport task5_ -- --nocapture
cargo test --test ssh_transport capability -- --nocapture
```

Expected: new flags, independent-failure cases, closed stat parsing, exact
follow-parent/mktemp forms, delete double-hash, hash-helper state restoration,
cleanup, and prior capability tests pass.

---

### Task 3: Make Fixed Execution Explicitly One-Shot and Mutation-Aware

**Files:**
- Modify: `src/ssh/process.rs`
- Modify: `src/ssh/mod.rs`
- Modify: `src/remote/mod.rs`
- Modify: `src/remote/metadata.rs`
- Modify: `src/remote/read.rs`
- Modify: `src/remote/search.rs`
- Modify: `tests/remote_ops.rs`
- Test: `src/ssh/process.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Produces: `FixedOperationKind::{ReadOnly, Mutation}`.
- Produces: `SshRunner::execute_fixed_once(FixedRunRequest, CancellationToken)`; it never retries.
- Preserves: Task 4's exact retry lives only in `RemoteBridge::execute_readonly_fixed`.
- Guarantees: post-spawn mutation failure is `MutationOutcomeUnknown` with the detail flag true.

- [ ] **Step 1: Add failing one-shot phase tests**

Inside `src/ssh/process.rs`, add a crate-local test fixture operation that uses
a static no-op mutation script and asserts these boundaries:

```rust
#[tokio::test]
async fn task5_mutation_phase_marks_only_post_spawn_ambiguity() {
    // cached false safe_write: REMOTE_CAPABILITY_MISSING, no mutation child
    // cancelled before runner call: CANCELLED, mutation flag absent
    // child exit 7: MUTATION_OUTCOME_UNKNOWN, flag true
    // child timeout/status 255/output overflow: same unknown code and one C log
}
```

Add a Task 4 regression that a strict read-only mismatch still produces two
`P`/`C` attempts, while a fixed mutation mismatch will later remain one child.

- [ ] **Step 2: Run runner tests and verify RED**

Run:

```bash
cargo test --lib ssh::process::tests::task5_mutation_phase_marks_only_post_spawn_ambiguity -- --exact --nocapture
```

Expected: compilation fails because operation kind and `execute_fixed_once` do not exist.

- [ ] **Step 3: Add operation kind and rename the one-attempt method**

In `src/ssh/process.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixedOperationKind {
    ReadOnly,
    Mutation,
}

#[derive(Clone)]
pub(crate) struct FixedRunRequest {
    pub kind: FixedOperationKind,
    // existing fields unchanged
}
```

Rename `execute_fixed` to `execute_fixed_once`. Update every Task 4 request to
`ReadOnly` and keep the sole invalidation/reprobe/second call inside
`execute_readonly_fixed`. Generalize the cached-false message from “read
capability” to “remote host lacks a required capability”.

- [ ] **Step 4: Track child-spawn state and classify mutation ambiguity**

Add a mutation command phase. Keep pre-spawn validation/initialization errors
unchanged. After `Command::spawn` succeeds, map every nonzero exit, timeout,
cancellation, output-limit, stdin/capture error, and status 255 for a Mutation
phase through:

```rust
fn mutation_unknown(mut source: BridgeError) -> BridgeError {
    let mut error = BridgeError::mutation_outcome_unknown();
    error.details.host = source.details.host.take();
    error.details.elapsed_ms = source.details.elapsed_ms;
    error.details.exit_status = source.details.exit_status;
    error.details.bytes_seen = source.details.bytes_seen;
    error.details.remote_process_may_continue = source.details.remote_process_may_continue;
    error
}
```

Do not copy source messages or stderr. Exit zero still returns private captured
output for strict facade parsing.

- [ ] **Step 5: Verify runner and Task 4 retry regressions**

Run:

```bash
cargo fmt --check
cargo test --lib ssh::process::tests::task5_mutation_phase_marks_only_post_spawn_ambiguity -- --exact --nocapture
cargo test --test remote_ops readonly_real_mismatch_retries_exactly_once_from_the_list_script -- --exact --nocapture
cargo test --test remote_ops capability_mismatch_unknown_key_is_protocol_error_without_retry -- --exact --nocapture
```

Expected: the mutation phase is one-shot and unknown after spawn; Task 4 behavior is unchanged.

---

### Task 4: Implement Strict Protocol Parsing and Safe Create

**Files:**
- Create: `src/remote/write.rs`
- Modify: `src/remote/mod.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Produces: `parse_write_protocol(&FixedRunResult, &ResolvedWrite) -> BridgeResult<WriteProtocol>`.
- Produces: static `WRITE_SCRIPT` and public `RemoteBridge::write` Create behavior.
- Consumes: `safe_write`, `FixedOperationKind::Mutation`, raw stdin, `InternalSpoolOwner`, and Task 4 context/path encoders.

- [ ] **Step 1: Add failing strict-protocol and Create tests**

Add tests for UTF-8, NUL, canonical Base64, empty content, exact hash/size,
remote context, final mode 0600, same-directory install, and no staging names.
Add zero-launch cases using `FAKE_SSH_LOG`: read-only host, empty/`.`/root
target, traversal, NUL, path over 64 KiB, invalid/missing-padding/URL-safe/
whitespace Base64, decoded bytes above `max_write_bytes`, malformed/uppercase
Replace expected hash, and exact rendered command plus
stdin above `max_frame_bytes`. Assert the log remains absent or empty.
The frame test must use the final render and a legal pathname containing many
single quotes so `shell_word` amplification plus stdin crosses the limit while
the unquoted estimate would not. Add success-protocol assertions that MODE is
decimal (`0600 -> 384`, `0640 -> 416`).
Add file/directory/live-symlink/dangling-symlink collisions and a hostile name:

```rust
let hostile = " -quote' line\n*?[$]`$(touch SHOULD_NOT_EXIST)`-雪 ";
let result = bridge.write(
    WriteRequest {
        host: "dev".into(),
        path: hostile.into(),
        content: "a\0b".into(),
        encoding: WriteEncoding::Utf8,
        mode: WriteMode::Create,
    },
    CancellationToken::new(),
).await.unwrap();
assert_eq!(std::fs::read(remote.path().join(hostile)).unwrap(), b"a\0b");
assert!(!remote.path().join("SHOULD_NOT_EXIST").exists());
assert_eq!(result.mode, 0o600);
assert!(result.temporary_cleanup_confirmed);
```

Add parser fixture cases for empty stderr requirement, exact terminal NUL,
unknown/duplicate/extra/trailing fields, mismatched operation/size/hash/mode,
and each allowed domain record. At the parser unit boundary assert
`ProtocolError`; through `write`, assert malformed post-child output becomes
unknown.

- [ ] **Step 2: Run Create tests and verify RED**

Run:

```bash
cargo test --test remote_ops task5_create_ -- --nocapture
cargo test --test remote_ops task5_write_protocol_ -- --nocapture
```

Expected: tests fail because the script/parser/orchestration are not implemented.

- [ ] **Step 3: Implement complete local resolution against the final script**

Register `mod write;` and add `RemoteBridge::write(request, cancel)`. In the
new module, decode canonical content with the existing Base64 engine:

```rust
fn decode_content(encoding: WriteEncoding, content: String) -> BridgeResult<Vec<u8>> {
    match encoding {
        WriteEncoding::Utf8 => Ok(content.into_bytes()),
        WriteEncoding::Base64 => STANDARD
            .decode(content)
            .map_err(|_| BridgeError::invalid_argument("write content is not canonical Base64")),
    }
}
```

`STANDARD` is base64 0.22's strict standard engine: canonical padding is
required and nonzero trailing bits are rejected. This is equivalent to an
exact decode/re-encode comparison without allocating a second full encoded
string. Tests freeze rejection of whitespace, URL-safe input, missing padding,
and noncanonical trailing bits.

Implement `resolve_write` with exact host/read-only/path/root/parent/basename,
decoded-size, expected-hash, local SHA-256, and checked
`render_fixed_command(WRITE_SCRIPT, args).len() + content.len()` validation.
Because the final `WRITE_SCRIPT` is now present in this task, the prelaunch
frame calculation uses the exact bytes the runner will execute.

Release the request/source string once its positional arguments and decoded
bytes are resolved. Move the single decoded `Vec<u8>` into runner stdin; never
clone it or allocate a second bridge-owned mutation-content buffer.

- [ ] **Step 4: Implement the strict NUL parser**

Read stdout/stderr from the forced internal spool with narrow fixed bounds.
Require empty stderr and parse only these exact ordered records:

```rust
enum WriteProtocol {
    Success { operation: WriteOperation, size: u64, sha256: String, mode: u32 },
    Domain(ErrorCode),
    CapabilityMismatch(&'static str),
}
```

Accept only success, `WriteConflict`, `NotFound`, `NotDirectory`,
`PermissionDenied`, and `CapabilityMismatch(safe_write)`. A recognized
capability mismatch invalidates the host cache for a future request, returns
`RemoteCapabilityMissing`, and does not call the runner again. Convert every
other post-child parser error to `mutation_outcome_unknown` at the facade.

- [ ] **Step 5: Implement cleanup, sentinel, stat, and no-follow hash helpers**

The static script begins with positional parsing and these concrete helper
boundaries:

```sh
tmp=
cleanup_tmp() {
    [ -z "$tmp" ] || rm -f -- "$tmp" >/dev/null 2>&1 || return 1
    [ -z "$tmp" ] || { [ ! -e "$tmp" ] && [ ! -L "$tmp" ]; } || return 1
    tmp=
}
on_signal() {
    trap - 0 HUP INT TERM
    cleanup_tmp >/dev/null 2>&1 || :
    exit 125
}
trap 'cleanup_tmp >/dev/null 2>&1 || :' 0
trap on_signal HUP INT TERM

emit_one() {
    cleanup_tmp || exit 90
    trap - 0 HUP INT TERM
    printf 'STATUS=%s\000' "$1"
    exit 0
}
```

Add compact `stat` field parsing using exactly one seven-field colon-separated
numeric ASCII line. Reject the whole line before splitting unless every byte is
in the closed numeric/colon set, then reject extra fields or invalid
hex/octal/decimal characters; never store NUL output in shell variables. Add a
no-follow path hash helper built from
the exact `codex_hash_nofollow` pipeline above. Parse the capture with POSIX
shell `case`/line iteration in a subshell with a unified result path so every
exit restores `IFS`; require one lowercase digest and both zero status lines,
and emit none of the capture to mutation stdout/stderr. Use the helper
for staging, precommit targets, and installed-target verification. The
sentinel must invoke the exact production parent-follow stat/final lstat/
same-directory mktemp/dd/stat/id/hash/chmod/ln/mv forms in private scratch
before parent access and emit only the exact CapabilityMismatch record on
semantic failure.

Parent entry uses POSIX `cd "$parent"`, never `cd --`. Capture the dereferenced
directory device/inode with the exact shared `parent_stat_follow` helper before
entry; after `cd` success, and before reading stdin or creating staging,
follow-stat `.` with the same helper and require the same identity. After `cd`
failure, return
`PermissionDenied` only if a second stat proves the same directory identity and
it remains unenterable. Missing/replaced/type-raced/unproved failures emit no
typed record and become unknown.

- [ ] **Step 6: Implement Create staging and hard-link commit**

Implement the exact ordered state machine from design §8:

```text
sentinel -> parent classify/cd -> initial no-entry guard -> umask/mktemp
-> raw-stdin dd oflag=nofollow -> temp type/uid/0600/size/hash/device/nlink=1
-> ln no-clobber -> same-inode/nlink=2 verify -> unlink temp
-> absent-temp + target nlink=1/mode/size/hash verify -> SUCCESS record
```

On `ln` failure, return `WriteConflict` only when lstat proves a destination
entry exists. Do not turn an unclassified utility failure into a false typed
result. Every result after staging calls verified cleanup first.

- [ ] **Step 7: Verify Create and strict protocol GREEN**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test remote_ops task5_create_ -- --nocapture
cargo test --test remote_ops task5_write_protocol_ -- --nocapture
```

Expected: exact creates pass, all existing/colliding entries conflict, hostile names remain data, and no staging name remains.

---

### Task 5: Implement Guarded Replace and Permission Finalization

**Files:**
- Modify: `src/remote/write.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- Extends: the one-shot `WRITE_SCRIPT` with Replace.
- Guarantees: final target regular/no-follow, optional final expected hash, identity/mode race guard, atomic content rename, and verified post-rename ordinary mode.

- [ ] **Step 1: Add failing Replace tests**

Add cases for missing, directory, FIFO, live/dangling symlink, special bits,
expected-hash mismatch, correct expected hash, `None` last-writer-wins,
ordinary modes 0000/0600/0640/0777, empty/binary content, and hostile path.
Assert old content remains on every proven precommit conflict.
Explicitly assert 0000 and 0200 succeed without any post-chmod content reopen.

Add deterministic PATH shims for:

- target inode replacement between initial and final lstat;
- chmod-only mode race;
- content change during expected hash;
- `chmod -h` failure after rename; and
- target changed to a symlink before chmod, with an outside referent whose mode
  and content must remain unchanged.

- [ ] **Step 2: Run Replace tests and verify RED**

Run:

```bash
cargo test --test remote_ops task5_replace_ -- --nocapture
```

Expected: Replace is missing or returns incorrect modes/conflicts.

- [ ] **Step 3: Implement initial and final target guards**

Use lstat-derived type bits, device, inode, full mode, and ordinary mode. Never
use a path-following `test -f` as the authoritative type decision. Reject
special low 07000 bits. Immediately before rename, recheck type, identity, and
mode. With `expected_sha256=Some`, run the no-follow hash helper, compare the
complete digest, and re-lstat identity/type/mode after hashing.

- [ ] **Step 4: Implement atomic rename and safe chmod finalization**

After full staging verification:

```text
capture staged dev/inode -> mv -T temp target -> confirm temp absent
-> lstat target is staged regular inode/owner/mode0600/size/hash
-> chmod -h preserved0777 -- target
-> lstat target same inode/non-symlink/owner/exact mode/frozen size/nlink1
-> confirm temp absent -> SUCCESS REPLACE record
```

The size/hash check before chmod is the final content open. Do not chmod staging
before rename and do not hash/reopen the target after chmod. Any failure from
successful rename through final verification must emit no typed success/error
and surface as unknown.

- [ ] **Step 5: Verify Replace GREEN and Create regression**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test remote_ops task5_replace_ -- --nocapture
cargo test --test remote_ops task5_create_ -- --nocapture
```

Expected: content replacement is atomic, ordinary modes are preserved, special/raced targets conflict before commit, and post-rename uncertainty is never false success.

Assert each successful fixed write reports `RemoteContext.shell` as POSIX sh.
Keep the existing `remote_run` Bash/sh fallback metadata tests in the regression
gate; Task 5 must not change arbitrary-command shell selection.

---

### Task 6: Prove Symlink/Race Defense, Exactly-Once, Cleanup, and Unknown Outcomes

**Files:**
- Modify: `tests/fixtures/fake-ssh.sh`
- Modify: `tests/remote_ops.rs`
- Modify: `src/remote/write.rs`
- Modify: `src/ssh/process.rs`

**Interfaces:**
- Verifies: the original exploit cannot modify an outside file.
- Verifies: all ambiguous mutation paths return one stable unknown result and never retry.
- Verifies: remote temp paths and local fixed spools clean up on normal/error/signal/abort paths.

- [ ] **Step 1: Add the deterministic original-exploit regression**

Prepend a `dd` shim that delegates probe/sentinel forms but, for the caller's
staging operand, replaces the created pathname with a symlink to an outside
sentinel immediately before executing real GNU `dd` with `oflag=nofollow`.
Assert:

```rust
assert_eq!(std::fs::read(&outside).unwrap(), b"OUTSIDE-SENTINEL");
assert_ne!(result.unwrap_err().code, ErrorCode::WriteConflict);
assert_eq!(ssh_log.lines().filter(|line| *line == "C").count(), 1);
assert!(remote_temp_names(remote.path()).is_empty());
```

The test must be deterministic and must not depend on guessing real random
suffixes or timing a polling loop.

- [ ] **Step 2: Add race, signal, and abort cleanup RED tests**

Add deterministic cases where a shim creates the target during upload,
replaces a final target with a dangling symlink, interrupts `dd`, and delays
stdin so cancellation occurs with a staging file present. Abort the facade
future after both local spool files appear. In every case assert outside files
unchanged, exactly one `C` command, no automatic reprobe/retry, no remote temp
name after bounded teardown, and no local internal spool after owner drop.

Also cover a legitimate symlink parent and a deterministic parent-entry race:
the exact follow-stat before `cd` observes one directory, a stateful shim
switches the symlink, and the follow-stat of `.` observes a different
device/inode. The script must fail before reading stdin or creating staging.

- [ ] **Step 3: Add post-commit ambiguity RED tests**

Extend fake SSH only as needed with controls that execute the fixed remote
command once, then either discard/replace its stdout or exit 255. Cover:

```text
commit then disconnect
commit then malformed/trailing stdout
success stdout plus nonempty stderr
post-rename chmod failure
timeout/cancel/output-limit after mutation child spawn
```

Assert `MUTATION_OUTCOME_UNKNOWN`, `retryable=false`,
`mutation_may_have_applied=true`, no `WriteResult`, no cleanup claim, redacted
diagnostics, and exactly one mutation child.

- [ ] **Step 4: Add stale-sentinel no-retry tests**

Use a stateful shim that passes the full probe, corrupts the first real
`safe_write` sentinel, and behaves normally later. The first write must return
`RemoteCapabilityMissing` with one probe and one mutation child; it must not
write content. A separately issued second write may reprobe because the cache
was invalidated and may then succeed, again with one mutation child. A
persistent mismatch returns capability missing on each independent call,
never two mutation attempts in one call.

Expand this into an exact-form matrix for both write and delete: parent-follow
stat, final lstat, dd input/output, hash, ln, mv, chmod, and rm. Every shim first
passes the full probe, then changes the real production form. Each mismatch
must occur before caller stdin/parent access, use exactly one mutation child,
never retry, invalidate future cache state, and allow only the next independent
call to reprobe.

- [ ] **Step 5: Add five-host buffer ownership and cleanup stress test**

Run five concurrent 4 MiB writes to five configured hosts. Record a controlled
resident-memory baseline and delta with a deliberately wide threshold, noting
the Base64 source transient rather than asserting a brittle absolute RSS.
Assert one moved decoded stdin buffer per call by construction, one child and
one staging file per host/call, correct results, and complete remote/local
cleanup.

- [ ] **Step 6: Implement only fixes exposed by the adversarial RED cases**

Keep fixes within the frozen state machine: no retries, no dynamic script
generation, no remote pre-stat child, no predictable name, and no downgrade to
path-following hash/chmod. Tighten cleanup/result parsing/phase mapping at the
specific failing boundary.

- [ ] **Step 7: Verify all adversarial cases GREEN**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test remote_ops task5_symlink_ -- --nocapture
cargo test --test remote_ops task5_cleanup_ -- --nocapture
cargo test --test remote_ops task5_unknown_ -- --nocapture
cargo test --test remote_ops task5_stale_write_sentinel_ -- --nocapture
```

Expected: the outside sentinel and symlink referents are unchanged, cleanup is complete, each API call has one mutation child, and every ambiguous result is unknown/non-retryable.

---

### Task 7: Implement and Verify Crate-Private Guarded Delete

**Files:**
- Modify: `src/remote/write.rs`
- Modify: `src/remote/mod.rs`
- Test: `src/remote/write.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Produces: `RemoteBridge::guarded_delete(GuardedDeleteRequest, CancellationToken)` for Task 6 only.
- Consumes: `guarded_delete` capability, mandatory expected SHA-256, one mutation child, strict result protocol.
- Does not produce: public serde type, MCP tool, patch behavior, or idempotent missing success.

- [ ] **Step 1: Add failing crate-local guarded-delete tests**

Inside `src/remote/write.rs`, add async tests with the same fake runner fixture
for success, missing, wrong hash, directory, FIFO, live/dangling symlink,
read-only, invalid local path/hash, identity/hash race, unlink failure,
post-unlink reappearance, cancellation, disconnect, stale sentinel, one-child
count, and absence confirmation.

The core success assertion is:

```rust
let result = bridge.guarded_delete(
    GuardedDeleteRequest {
        host: "dev".into(),
        path: "victim".into(),
        expected_sha256: sha256(b"victim"),
    },
    CancellationToken::new(),
).await.unwrap();
assert!(!remote.path().join("victim").exists());
assert_eq!(result.deleted_sha256, sha256(b"victim"));
assert!(result.absence_confirmed);
```

- [ ] **Step 2: Run guarded-delete tests and verify RED**

Run:

```bash
cargo test --lib remote::write::tests::task5_guarded_delete -- --nocapture
```

Expected: tests fail because `guarded_delete` and its static protocol are absent.

- [ ] **Step 3: Implement the one-shot delete script and parser**

Implement the exact sequence:

```text
local validation -> guarded_delete sentinel -> parent classify/cd
-> pre-follow identity equals post-cd follow-stat of `.`
-> lstat existing regular non-symlink -> capture dev/inode
-> no-follow full expected hash -> repeat lstat identity/type
-> no-follow full expected hash immediately before rm
-> rm -f -- target -> confirm !-e and !-L -> SUCCESS DELETE record
```

Return `NotFound` for missing and `WriteConflict` for type/symlink/hash/identity
before unlink. Any unclosed or post-unlink ambiguous outcome is unknown. Parse
only the exact Delete success/domain/capability records; invalidate future
capability state without retry on the strict pre-target mismatch.

- [ ] **Step 4: Verify guarded delete GREEN and no public surface**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --lib remote::write::tests::task5_guarded_delete -- --nocapture
rg -n "guarded_delete|GuardedDelete" src | sort
```

Expected: all delete tests pass; search shows only crate-private Task 5 remote/runner code and tests, with no MCP/CLI/patch files.

---

### Task 8: Full Regression, Review, Report, and Single Commit

**Files:**
- Modify: any Task 5 file above only for verified defects
- Create: `.superpowers/sdd/task-5-report.md`
- Include: Task 5 design and plan documents

**Interfaces:**
- Produces: verified Task 5 commit and controller review package.
- Preserves: all Task 1-4 behavior and the no-Python/no-Task6 boundaries.

- [ ] **Step 1: Run formatting and lint from a clean command invocation**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: both exit 0 with no warnings.

- [ ] **Step 2: Run focused Task 5 and Task 4 regression suites**

Run:

```bash
cargo test --test remote_ops -- --nocapture
cargo test --test ssh_transport -- --nocapture
```

Expected: all tests pass, including attack, exactly-once, bounded cleanup, capability, and existing remote-read cases.

- [ ] **Step 3: Run the full target suite**

Run:

```bash
cargo test --all-targets
```

Expected: all targets pass. Any platform skip remains explicit and is not summarized as a pass for the skipped facility.

- [ ] **Step 4: Audit forbidden scope, retry calls, scripts, and worktree state**

Run:

```bash
rg -n "execute_readonly_fixed|execute_fixed_once|FixedOperationKind" src/remote src/ssh
rg -n "python3|python" Cargo.toml src tests/fixtures tests/remote_ops.rs tests/ssh_transport.rs
git diff --check
git status --short
```

Expected: writes/deletes call one-shot mutation execution only; Task 4 owns the only optional retry; no Python appears in the Rust runtime/test fixture chain; diff check passes; only Task 5 files plus pre-existing pycache are changed/untracked.

- [ ] **Step 5: Write the Task 5 report with fresh evidence**

Create `.superpowers/sdd/task-5-report.md` containing:

```markdown
# Task 5 Report

## Scope
Safe one-shot create/replace plus crate-private guarded delete; no Task 6/MCP/CLI changes.

## Verification
- `cargo fmt --check`: exit 0
- `cargo clippy --all-targets --all-features -- -D warnings`: exit 0
- `cargo test --test remote_ops -- --nocapture`: record the fresh harness summary verbatim
- `cargo test --test ssh_transport -- --nocapture`: record the fresh harness summary verbatim
- `cargo test --all-targets`: record every fresh harness summary and explicit skip verbatim

## Security Evidence
- original staging-symlink exploit leaves outside sentinel unchanged
- create hard-link collision never clobbers
- replace expected hash/type/mode races fail before commit when provable
- post-commit ambiguity returns `MUTATION_OUTCOME_UNKNOWN` and never retries
- remote staging and local internal spools clean on normal/error/signal/abort paths
- guarded delete requires expected hash and regular non-symlink target

## Files and Commit
List every staged Task 5 path and the intended commit subject. A Git commit
cannot contain its own hash; report the resulting hash to the controller after
the commit instead of writing a self-referential field here.

## Residual Boundary
The remote account and malicious same-account processes share the SSH security boundary; shell utilities do not provide perfect compare-and-swap/unlink against that actor.
```

Replace the prose recording instructions with the fresh observed values before commit.

- [ ] **Step 6: Review the final diff, preserve pycache, and create one commit**

Run:

```bash
git diff --stat
git diff -- src/error.rs src/capability.rs src/ssh src/remote tests/fixtures/fake-ssh.sh tests/ssh_transport.rs tests/remote_ops.rs docs/superpowers/specs/2026-07-18-task-5-safe-atomic-write-design.md docs/superpowers/plans/2026-07-18-task-5-safe-atomic-write.md .superpowers/sdd/task-5-report.md
git status --short
```

Stage only the reviewed Task 5 paths, explicitly excluding both pycache directories, then commit once:

```bash
git add src/error.rs src/capability.rs src/ssh src/remote tests/fixtures/fake-ssh.sh tests/ssh_transport.rs tests/remote_ops.rs docs/superpowers/specs/2026-07-18-task-5-safe-atomic-write-design.md docs/superpowers/plans/2026-07-18-task-5-safe-atomic-write.md .superpowers/sdd/task-5-report.md
git commit -m "feat: add symlink-safe remote writes"
```

Expected: one new commit; `ssh_bridge/__pycache__/` and `tests/__pycache__/` remain untouched and untracked.
