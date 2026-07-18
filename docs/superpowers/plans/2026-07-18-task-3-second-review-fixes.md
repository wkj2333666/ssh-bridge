# Task 3 Second-Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct GNU timeout capability/rendering, supervise blocked stdin, and make spool cleanup and file modes ownership-safe.

**Architecture:** Keep the existing runner and output-store boundaries. Extend the runner's select loop from two supervised operations to three, strengthen the fixed capability script through a functional probe, and make spool file ownership explicit during partial construction.

**Tech Stack:** Rust 2024, Tokio, tokio-util cancellation tokens, POSIX shell fixtures, GNU coreutils timeout.

## Global Constraints

- Preserve every existing test and the public Task 3 API.
- Use integer-only `secs.{millis:03}s` duration rendering and typed rejection of zero.
- Keep TERM 50 ms plus bounded drain/join within the existing 250 ms forced-return budget.
- Never mutate process-global umask in the test runner; set it only in an exec-isolated child.
- Make one final review-fix commit containing code, tests, design, plan, and report updates.

---

### Task 1: GNU timeout rendering and functional probe

**Files:**
- Modify: `src/ssh/process.rs`
- Modify: `src/capability.rs`
- Test: `src/ssh/process.rs`
- Test: `tests/ssh_transport.rs`

**Interfaces:**
- Produces: `format_timeout_duration(timeout_ms: u64) -> BridgeResult<String>`.
- Preserves: `render_remote_command(..., timeout_ms: u64) -> BridgeResult<String>`.

- [ ] **Step 1: Write failing timeout tests**

Add a process unit regression that asserts `123 -> 0.123s`, `1000 -> 1.000s`, rejects zero, and executes the rendered command through `/bin/sh` using real `/usr/bin/timeout`. Update the existing integration expectation from `123ms` to `0.123s`. Add a capability-probe regression whose PATH-first fake `timeout` exits 125 and therefore must yield `TOOL_timeout=0` without protocol contamination.

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo test --lib remote_timeout_uses_gnu_decimal_seconds -- --nocapture
cargo test --test ssh_transport selected_shell_and_remote_gnu_timeout_are_reported_and_rendered_exactly -- --exact --nocapture
cargo test --test ssh_transport capability_probe_functionally_rejects_an_incompatible_timeout -- --exact --nocapture
```

Expected: the first test observes status 125 or `123ms`, the integration expectation differs, and the probe incorrectly reports `TOOL_timeout=1`.

- [ ] **Step 3: Implement the minimum formatter and probe**

Use checked integer decomposition:

```rust
fn format_timeout_duration(timeout_ms: u64) -> BridgeResult<String> {
    if timeout_ms == 0 {
        return Err(BridgeError::invalid_argument("command timeout must be positive"));
    }
    let seconds = timeout_ms / 1000;
    let milliseconds = timeout_ms % 1000;
    Ok(format!("{seconds}.{milliseconds:03}s"))
}
```

Render that value after the required options. In `CAPABILITY_PROBE_SCRIPT`, replace `has_tool timeout` with a function that runs:

```sh
timeout --signal=TERM --kill-after=1s 1.000s sh -c 'exit 0' >/dev/null 2>&1
```

and emits 1 only for exit zero.

- [ ] **Step 4: Verify GREEN**

Re-run all three commands; expected: PASS.

### Task 2: Supervise stdin with child wait and output capture

**Files:**
- Modify: `tests/fixtures/fake-ssh.sh`
- Modify: `tests/ssh_transport.rs`
- Modify: `src/ssh/process.rs`

**Interfaces:**
- Produces: `joined_stdin(...) -> BridgeResult<()>` and `finish_stdin_bounded(...) -> BridgeResult<()>`.
- Preserves: `SshRunner::execute` cancellation/deadline error details.

- [ ] **Step 1: Write failing orphan-stdin tests**

Add `orphan-stdin` to the fixture: a TERM/HUP-ignoring descendant redirects stdout/stderr to `/dev/null`, retains stdin, records its PID, and the SSH parent records exit then exits. Add cancellation and 80 ms deadline tests with exactly `MAX_WRITE_BYTES` input, outer watchdogs, PID cleanup on RED, `<=250ms` cancellation assertions, and `remote_process_may_continue=Some(true)`.

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo test --test ssh_transport orphan_stdin -- --nocapture
```

Expected: both watchdog paths show the runner stuck after child and capture completion.

- [ ] **Step 3: Implement the unified lifecycle**

Track `stdin_finished` alongside `status` and `capture`; add the stdin JoinHandle to the same biased `tokio::select!`; enter `Stop::Completed` only when all three are complete. On forced termination, if stdin is unfinished, wait at most `DRAIN_GRACE` (125 ms), then abort and join the task. Do not apply this bound to normal stdin delivery.

- [ ] **Step 4: Verify GREEN and normal stdin**

Run:

```bash
cargo test --test ssh_transport orphan_stdin -- --nocapture
cargo test --test ssh_transport command_stdin_is_streamed_and_oversized_input_is_rejected_before_ssh -- --exact --nocapture
```

Expected: all pass, with cancellation inside 250 ms and full normal stdin echoed.

### Task 3: Preserve unowned stderr collisions

**Files:**
- Modify: `src/output.rs`

**Interfaces:**
- Preserves: `PendingSpool.stderr: Option<tokio::fs::File>` as the ownership flag.

- [ ] **Step 1: Write the failing partial-construction test**

Construct a `PendingSpool` with an owned stdout file, a pre-existing sentinel stderr path, and `stderr: None`; drop it; assert stdout was removed and the sentinel bytes remain unchanged.

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo test --lib dropping_a_partial_spool_preserves_an_unowned_stderr_collision -- --nocapture
```

Expected: FAIL because Drop unlinks the sentinel stderr path.

- [ ] **Step 3: Implement ownership-aware Drop**

Capture `let owns_stderr = self.stderr.is_some();`, always remove owned stdout, and remove stderr only when `owns_stderr` is true.

- [ ] **Step 4: Verify GREEN**

Re-run the test plus `dropping_an_unregistered_spool_removes_both_files`; expected: both PASS.

### Task 4: Enforce mode 0600 independently of umask

**Files:**
- Modify: `src/output.rs`
- Modify: `tests/ssh_transport.rs`

**Interfaces:**
- Preserves: `create_private_file(path: &Path) -> io::Result<std::fs::File>`.

- [ ] **Step 1: Write the failing isolated-umask test**

Launch the current integration-test executable via `/bin/sh -c 'umask 0777; exec "$@"'`. In the sentinel child, capture more than 256 KiB, assert both spool modes are exactly 0600, and page stdout successfully.

- [ ] **Step 2: Verify RED**

Run:

```bash
cargo test --test ssh_transport spool_files_are_mode_0600_under_restrictive_umask -- --exact --nocapture
```

Expected: child assertion reports mode 000 instead of 0600.

- [ ] **Step 3: Apply permissions through the open file**

After `create_new`, call:

```rust
file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
```

If permission setting fails, close and unlink only the newly owned path before returning the I/O error.

- [ ] **Step 4: Verify GREEN**

Re-run the isolated test and the existing exact-64-MiB paging test; expected: PASS.

### Task 5: Documentation, gates, and commit

**Files:**
- Modify: `.superpowers/sdd/task-3-report.md` (workspace report, intentionally ignored)
- Modify: `.superpowers/sdd/task-3-clarifications.md` (workspace binding record, intentionally ignored)
- Add: `docs/superpowers/specs/2026-07-18-task-3-second-review-fixes-design.md`
- Add: `docs/superpowers/plans/2026-07-18-task-3-second-review-fixes.md`

- [ ] **Step 1: Update evidence**

Record each RED symptom, GREEN command, final counts, and the new commit in the report. Preserve both earlier commits as history.

- [ ] **Step 2: Run fresh full gates**

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test ssh_transport -- --nocapture
cargo test --all-targets --all-features
git diff --check
```

Expected: every command exits 0 with no failures or warnings.

- [ ] **Step 3: Review and commit explicit paths**

```bash
git add src/capability.rs src/output.rs src/ssh/process.rs tests/fixtures/fake-ssh.sh tests/ssh_transport.rs docs/superpowers/specs/2026-07-18-task-3-second-review-fixes-design.md docs/superpowers/plans/2026-07-18-task-3-second-review-fixes.md
git diff --cached --check
git commit -m "fix: complete SSH runner lifecycle hardening"
```

Leave the unrelated `ssh_bridge/__pycache__/` and `tests/__pycache__/` untracked and untouched.
