# Persistent Remote Helper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (recommended) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install the Rust helper once per bridge-version/remote-target on each host, reuse it for later cold connections, and leave warm requests byte-for-byte on the existing HostSession path.

**Architecture:** The local bridge adds an installation-aware bootstrap to cold SSH setup. The bootstrap sends a bounded `CXSB-INSTALL-1 HIT|NEED` line before the helper's normal framed handshake, validates a versioned helper file under the remote user's home, and receives helper bytes only on `NEED`. The existing temporary upload and POSIX dispatcher remain ordered fallbacks. `HostSession` records the selected transport mode, while request execution and multiplexing are unchanged.

**Tech Stack:** Rust 1.91.1, existing Tokio SSH/session runtime, standard POSIX shell bootstrap, `sha2`, fake-SSH integration fixtures, Cargo tests, opt-in profile feature.

## Global Constraints

- Warm requests must not perform remote installation probes, hash checks, lock operations, uploads, or extra SSH calls.
- A bridge process owns one reusable HostSession per host; cold initialization is serialized per host by `session_initializers`.
- The persistent helper file is under `~/.local/share/codex-ssh-bridge/helpers/VERSION/TARGET/helper`, mode `0700`, and is never added to `PATH`.
- Helper bytes are sent only after an exact `CXSB-INSTALL-1 NEED\n` status; a `HIT` status sends zero helper bytes.
- The remote final file is reached only by atomic rename after exact-length and SHA-256 validation.
- A pre-request persistent failure may fall back to temporary helper and then the existing shell dispatcher; a post-acceptance transport failure is never silently retried.
- MCP tool schemas and requested shell semantics remain unchanged; Bash remains the default and explicit Bash absence is reported as a capability error.
- No remote daemon, system service, shell startup modification, `PATH` modification, privilege escalation, remote compiler, or automatic old-version deletion.
- All diagnostics are bounded and must not expose helper bytes, credentials, command contents, or local secret paths.
- Profile output is opt-in and diagnostic only; acceptance measurements separate cold installation, cold reuse, and warm requests.

---

### Task 1: Define persistent bootstrap identities and pure negotiation helpers

**Files:**
- Modify: `src/ssh/helper.rs`
- Modify: `src/ssh/session.rs`
- Modify: `src/ssh/mod.rs`
- Test: `src/ssh/helper.rs` (module tests)
- Test: `src/ssh/session.rs` (module tests)

**Interfaces:**
- Add `pub(crate) const BRIDGE_VERSION: &str = env!("CARGO_PKG_VERSION")` in `src/ssh/helper.rs`.
- Add `pub enum HelperMode { Persistent, Temporary, Shell }` in `src/ssh/mod.rs`, deriving `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, and `Serialize` with lowercase wire names; keep a stable `as_str()` returning `persistent`, `temporary`, or `shell`.
- Add `pub(crate) struct HelperIdentity { version: String, target: &'static str, arch: &'static str, length: usize, sha256: String }`.
- Add `pub(crate) enum BootstrapStatus { Hit, Need }`.
- Add `pub(crate) fn helper_identity(artifact: &HelperArtifact, bytes: &[u8]) -> BridgeResult<HelperIdentity>`; reject empty/over-limit bytes and compute lowercase SHA-256 with the existing `sha2` dependency.
- Add `pub(crate) fn parse_bootstrap_status(bytes: &[u8]) -> BridgeResult<BootstrapStatus>`; accept exactly `CXSB-INSTALL-1 HIT\n` or `CXSB-INSTALL-1 NEED\n`, reject NUL, extra bytes, missing newline, and lines over 64 bytes.
- Change `HostSession` state from `helper: bool` to `helper_mode: HelperMode`; expose `pub(crate) fn helper_mode(&self) -> HelperMode` for result propagation.

- [ ] **Step 1: Write the failing pure tests.**

Add tests named `helper_identity_uses_exact_length_and_sha256`, `bootstrap_status_accepts_only_hit_or_need`, and `bootstrap_status_rejects_trailing_or_unbounded_data`. Assert the SHA-256 of `b"abc"` is `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`; assert malformed statuses return `ErrorCode::ProtocolError`.

- [ ] **Step 2: Run the focused tests and verify the expected failure.**

Run:

```bash
cargo test --lib ssh::helper::tests::helper_identity_uses_exact_length_and_sha256
cargo test --lib ssh::session::tests::bootstrap_status_accepts_only_hit_or_need
```

Expected result before implementation: compilation errors for the missing identity, status parser, and helper-mode interfaces.

- [ ] **Step 3: Implement the pure helpers.**

Use `Sha256::digest(bytes)` and a fixed two-digit lowercase formatter; do not invoke a subprocess for local hashing. Keep status parsing independent of Tokio and the SSH child so it can be tested with byte slices.

- [ ] **Step 4: Run the focused tests and the existing helper/session unit tests.**

Run:

```bash
cargo test --lib ssh::helper::tests ssh::session::tests
```

Expected result: all focused tests pass and no existing handshake or cancellation test changes behavior.

- [ ] **Step 5: Commit the pure negotiation layer.**

```bash
git add src/ssh/helper.rs src/ssh/session.rs src/ssh/mod.rs
git commit -m "feat: define persistent helper negotiation state"
```

### Task 2: Implement the installation-aware remote bootstrap

**Files:**
- Modify: `src/ssh/helper.rs`
- Modify: `tests/fixtures/fake-ssh.sh`
- Test: `src/ssh/helper.rs` (bootstrap tests)
- Test: `tests/session.rs`

**Interfaces:**
- Replace the temporary-only `helper_command(max_frame_bytes, helper_length)` path with `persistent_helper_command(max_frame_bytes, identity: &HelperIdentity) -> BridgeResult<String>`.
- Keep `helper_command(max_frame_bytes, helper_length)` for the temporary fallback unchanged apart from shared quoting utilities.
- The persistent command must pass only fixed shell-quoted arguments: bootstrap tag, max frame, bridge version, target, architecture, length, SHA-256, and destination components; helper bytes never enter the command string.
- The bootstrap prints one bounded status line, reads exact bytes only for `NEED`, validates the remote regular file/mode/length/hash, installs with a unique temporary file and atomic `mv`, releases its lock, and `exec`s the destination.
- Add fake-SSH environment controls `FAKE_SSH_PERSISTENT_HELPER_ROOT`, `FAKE_SSH_PERSISTENT_HELPER_MODE=hit|need|invalid|fail`, `FAKE_SSH_HELPER_BYTES_LOG`, and `FAKE_SSH_INSTALL_LOG` so tests can count uploaded bytes and inspect committed paths without a network.

- [ ] **Step 1: Add failing bootstrap tests.**

Add tests named `persistent_bootstrap_contains_no_helper_bytes`, `persistent_bootstrap_round_trips_hit_without_upload`, `persistent_bootstrap_round_trips_need_with_binary_bytes`, and `persistent_bootstrap_uses_atomic_target_install`. The `NEED` fixture must include NUL, newline, and `0xff` bytes and assert the installed file equals the original bytes. Assert the command contains `CXSB-INSTALL-1` and the target/version arguments but not the helper payload.

- [ ] **Step 2: Run the focused bootstrap tests and confirm RED.**

Run:

```bash
cargo test --lib ssh::helper::tests::persistent_bootstrap
cargo test --test session persistent_bootstrap
```

Expected result before implementation: missing command builder/status negotiation or the fixture still reports the old temporary-only behavior.

- [ ] **Step 3: Implement the fixed bootstrap script.**

Resolve the destination from shell tilde expansion into an absolute path under the authenticated account's home. Create version/target directories with `umask 077`; reject non-absolute or group/other-writable paths. Use `mkdir` as the advisory lock, bounded polling, and a unique temporary filename. For an existing candidate, check regular executable mode, exact byte length, and `sha256sum`; emit `HIT` only when all checks pass. For `NEED`, read exactly `length` bytes with bounded `dd` chunks, verify count and hash, `chmod 700`, then `mv` the temporary file into place.

- [ ] **Step 4: Extend the fake SSH fixture and run the tests GREEN.**

Make `tests/fixtures/fake-ssh.sh` recognize `codex-ssh-persistent-helper-bootstrap-1`, map the destination into `FAKE_SSH_PERSISTENT_HELPER_ROOT`, and execute the real `/bin/sh -c` command with a temporary HOME. Record `HIT`/`NEED`, upload byte count, and final target path in the configured logs. Run:

```bash
cargo test --lib ssh::helper::tests --test session persistent_bootstrap
```

Expected result: all bootstrap tests pass, including exact binary bytes and no upload on `HIT`.

- [ ] **Step 5: Commit the bootstrap implementation.**

```bash
git add src/ssh/helper.rs tests/fixtures/fake-ssh.sh tests/session.rs
git commit -m "feat: persist remote helper with atomic bootstrap"
```

### Task 3: Integrate cold-session negotiation and fallback ordering

**Files:**
- Modify: `src/ssh/session.rs`
- Modify: `src/ssh/helper.rs`
- Modify: `tests/session.rs`
- Modify: `tests/ssh_transport.rs`

**Interfaces:**
- `HostSession::connect_with_capability` tries persistent helper first when a matching local artifact exists; it passes the helper identity and parses the bootstrap status before the helper frame handshake.
- On `HIT`, the local bridge writes zero helper bytes and immediately parses `protocol=codex-ssh-helper/1;version=1;arch=...`.
- On `NEED`, it writes exactly `HelperIdentity::length` bytes, flushes, and then parses the same helper handshake.
- Persistent startup failures before request acceptance call the existing temporary helper path once; temporary startup failures then call the shell dispatcher once. Cancellation and invalid-argument errors do not trigger fallback.
- A successful `HostSession` stores `HelperMode::Persistent`, `HelperMode::Temporary`, or `HelperMode::Shell`; `HostSession::execute` does not branch on installation state.

- [ ] **Step 1: Add failing integration tests.**

Add `cold_session_reuses_persistent_helper_without_second_upload`, `bridge_restart_reuses_persistent_helper_file`, `invalid_persistent_hash_reinstalls_atomically`, `persistent_startup_failure_falls_back_to_temporary_then_shell`, and `concurrent_first_requests_share_one_installation`. Use the fake SSH byte log to assert first connection sends helper bytes, second connection sends zero, and two concurrent cold requests create one final target.

- [ ] **Step 2: Run the tests and verify RED.**

Run:

```bash
cargo test --test session cold_session_reuses_persistent_helper_without_second_upload
cargo test --test session persistent_startup_failure_falls_back_to_temporary_then_shell
```

Expected result before implementation: the existing code always chooses the temporary bootstrap and cannot parse `CXSB-INSTALL-1`.

- [ ] **Step 3: Implement persistent-first connection setup.**

Keep `connect_with_mode` responsible for one SSH child and one handshake. Add a cold-only bootstrap preamble reader using `BufReader::read_until(b'\n')`; parse it with `parse_bootstrap_status`. On `NEED`, write the bytes before waiting for `HELLO_ACK`; on `HIT`, do not write them. Ensure the bootstrap preamble is consumed exactly once and never reaches `read_frame` or a warm request.

- [ ] **Step 4: Preserve fallback and cancellation semantics.**

Reuse `helper_startup_fallback_allowed` for persistent and temporary pre-request errors, but never fallback after a `FrameKind::Open` has been sent. Close and wait for each failed SSH child before the next attempt. Keep shell `READY` acceptance and existing process-group shutdown unchanged.

- [ ] **Step 5: Run the complete session/transport suite.**

Run:

```bash
cargo test --test session --test ssh_transport --test dispatcher --test remote_helper
```

Expected result: persistent `HIT`/`NEED`, temporary helper, shell dispatcher, concurrency, cancellation, and existing capability tests all pass.

- [ ] **Step 6: Commit cold-session integration.**

```bash
git add src/ssh/session.rs src/ssh/helper.rs tests/session.rs tests/ssh_transport.rs
git commit -m "feat: reuse persistent helper across SSH sessions"
```

### Task 4: Propagate transport mode without changing the warm request path

**Files:**
- Modify: `src/ssh/session.rs`
- Modify: `src/ssh/process.rs`
- Modify: `src/remote/mod.rs`
- Modify: `src/remote/protocol.rs`
- Modify: `src/remote/run.rs`
- Modify: `src/output.rs`
- Modify: `src/remote/read.rs`
- Modify: `src/remote/patch.rs`
- Modify: `src/mcp/render.rs`
- Test: `tests/remote_ops.rs`
- Test: `tests/performance_acceptance.rs`

**Interfaces:**
- Add `pub(crate) helper_mode: HelperMode` to `RunResult` and `FixedRunResult`.
- Add `pub(crate) helper_mode: HelperMode` to `OutputProvenance` so `remote_output_read` retains the same transport metadata.
- Add `pub helper_mode: Option<HelperMode>` to `RemoteContext` with `#[serde(skip_serializing_if = "Option::is_none")]`; serialize values as `persistent`, `temporary`, and `shell`.
- `protocol::context(host, physical_root, shell, helper_mode)` and all fixed-operation context constructors set the selected mode.
- Add `helper_mode` to `RemoteRunResult` conversion and include it in `remote_run` structured metadata. Existing callers that construct contexts in tests use `Some(HelperMode::Shell)`.

- [ ] **Step 1: Add failing metadata tests.**

Add tests that convert a `RunResult` with `HelperMode::Persistent` and assert `structuredContent.helper_mode == "persistent"`; convert temporary and shell results and assert the other values. Add a retention test that `remote_output_read` preserves the mode from `OutputProvenance`. Add a compact-result test proving the field is bounded and does not expose paths.

- [ ] **Step 2: Run focused tests and verify RED.**

Run:

```bash
cargo test --test remote_ops helper_mode_is_rendered
cargo test --test performance_acceptance helper_mode_is_bounded
```

Expected result before implementation: `RemoteContext` and `RunResult` have no transport field.

- [ ] **Step 3: Thread the selected mode through successful and error paths.**

Copy the mode from the cached `HostSession` immediately after `session_for_host` returns; do not call any remote method to compute it. Attach it to `RunResult`/`FixedRunResult`, pass it into protocol context constructors, and preserve it in output provenance. Keep `SessionRequest::execute`, frame construction, queueing, capture, and output drain untouched.

- [ ] **Step 4: Run all MCP rendering and remote-operation regressions.**

Run:

```bash
cargo test --test remote_ops --test mcp_tools --test mcp_protocol --test performance_acceptance
```

Expected result: all existing fields retain their names and values, and the new optional field appears only in remote contexts produced after a session is established.

- [ ] **Step 5: Commit transport metadata propagation.**

```bash
git add src/ssh/session.rs src/ssh/process.rs src/remote src/mcp/render.rs tests/remote_ops.rs tests/performance_acceptance.rs
git commit -m "feat: report selected remote helper mode"
```

### Task 5: Add security, race, interruption, and fallback regression coverage

**Files:**
- Modify: `src/ssh/helper.rs`
- Modify: `tests/fixtures/fake-ssh.sh`
- Modify: `tests/session.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/real_ssh.rs`

**Interfaces:**
- Keep all security checks cold-only and local to bootstrap/session setup.
- The fixture exposes a deterministic interrupted upload and stale-lock mode; no test deletes an arbitrary user directory.
- Real-host tests remain opt-in under `CODEX_SSH_BRIDGE_HELPER_INTEGRATION=1` and use a private temporary HOME on the test account.

- [ ] **Step 1: Write failing security/race tests.**

Add tests for symlink destination rejection, group/other-writable destination rejection, short upload rejection without replacing a valid old helper, stale lock bounded takeover, concurrent installers producing one valid hash, and an unsupported architecture selecting shell mode with a diagnostic reason.

- [ ] **Step 2: Run the focused tests and verify RED.**

Run:

```bash
cargo test --test session persistent_helper_rejects_unsafe_destination
cargo test --test session persistent_helper_survives_interrupted_upload
cargo test --test ssh_transport unsupported_architecture_reports_shell_mode
```

Expected result before implementation: the fake fixture lacks persistent lock/hash/interruption controls and the current bridge has no persistent security path.

- [ ] **Step 3: Implement bounded lock and failure behavior.**

Use a lock directory under the version/target directory, poll only during cold startup, bound the wait, and fall back to a unique temporary candidate when the lock cannot be safely acquired. Never remove an active final helper. Treat an incomplete upload as untrusted temporary data and release the lock on all shell exits with a trap.

- [ ] **Step 4: Run security and real-SSH regressions.**

Run:

```bash
cargo test --test session --test ssh_transport --test real_ssh
```

Expected result: all tests pass; the real-host suite remains skipped unless its explicit integration environment variable is set.

- [ ] **Step 5: Commit the regression coverage.**

```bash
git add src/ssh/helper.rs tests/fixtures/fake-ssh.sh tests/session.rs tests/ssh_transport.rs tests/real_ssh.rs
git commit -m "test: cover persistent helper races and fallback safety"
```

### Task 6: Add cold/warm performance acceptance and profile phases

**Files:**
- Modify: `src/profile.rs`
- Modify: `src/ssh/session.rs`
- Modify: `src/ssh/process.rs`
- Modify: `tests/performance_acceptance.rs`
- Modify: `docs/performance.md`

**Interfaces:**
- Add opt-in profile phases `helper_install_probe`, `helper_install_upload`, and `helper_handshake`; keep existing `helper_frame_write`, `helper_command_spawn`, `helper_output_drain`, and `helper_exit` phases unchanged.
- Add a release-only acceptance test that records p50/p95 for first install, persistent-file cold reuse, warm persistent helper, and warm shell dispatcher.
- The test records helper upload byte count and asserts the second persistent connection reports zero uploaded bytes.

- [ ] **Step 1: Add the failing acceptance assertions.**

Extend `task12_helper_release_path` with a persistent fixture. Assert `warm_persistent_upload_bytes == 0`, assert the warm profile has no `helper_install_*` phase, and print separate labels `persistent_install_cold`, `persistent_reuse_cold`, `persistent_warm`, and `shell_warm`.

- [ ] **Step 2: Run the focused acceptance test and verify RED.**

Run:

```bash
cargo test --release --test performance_acceptance task12_helper_release_path -- --nocapture
```

Expected result before implementation: the fixture cannot distinguish persistent upload and the new zero-upload assertion fails.

- [ ] **Step 3: Add cold-only profile spans and fixture counters.**

Create the profile spans around status parsing, conditional upload, and helper handshake in `HostSession::connect_with_mode`. Do not add spans or checks inside `HostSession::execute`. Extend the fixture logs to record byte counts without recording command contents.

- [ ] **Step 4: Run performance and profile verification.**

Run:

```bash
cargo test --release --test performance_acceptance task12_helper_release_path -- --nocapture
CODEX_SSH_BRIDGE_PROFILE=1 cargo test --release --test performance_acceptance task12_helper_release_path -- --nocapture
```

Expected result: warm requests contain only normal request phases; cold output shows installation phases; the test reports cold and warm distributions separately.

- [ ] **Step 5: Commit performance instrumentation and acceptance tests.**

```bash
git add src/profile.rs src/ssh/session.rs src/ssh/process.rs tests/performance_acceptance.rs docs/performance.md
git commit -m "test: measure persistent helper cold and warm paths"
```

### Task 7: Update public documentation and perform full verification

**Files:**
- Modify: `README.md`
- Modify: `docs/security.md`
- Modify: `docs/performance.md`
- Modify: `tests/packaging.rs`
- Modify: `.github/workflows/ci.yml` only if packaging checks need the persistent helper layout

**Interfaces:**
- README describes the persistent remote location, per-session process lifecycle, fallback order, `helper_mode`, and the explicit manual cleanup command:

```bash
ssh ALIAS -- 'find ~/.local/share/codex-ssh-bridge/helpers -mindepth 1 -maxdepth 1 -type d -exec rm -rf -- {} +'
```

  The documentation must warn that this command removes all installed bridge helper versions for that account and must be run only with a verified alias.
- Security documentation states that installation uses the SSH account's home, private permissions, exact bytes, SHA-256, atomic rename, and no daemon/service.
- Performance documentation separates first install, persistent cold reuse, and warm request costs and explicitly states that warm requests do not probe or upload.
- Packaging tests assert every release archive still contains the main binary and all six helper targets; no remote helper is added to the public source package.

- [ ] **Step 1: Update documentation and add packaging assertions.**

Replace the README statement that neither path installs persistent material with the approved persistent-helper wording. Add examples showing `helper_mode=persistent` and the shell fallback warning. Add a test that fails if the archive omits any helper target.

- [ ] **Step 2: Run documentation/package checks.**

Run:

```bash
cargo test --test packaging --test cli
git diff --check
```

Expected result: all package and CLI tests pass and the documentation contains no machine-specific paths or credentials.

- [ ] **Step 3: Run the complete verification gate.**

Run:

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release --bins
```

Expected result: exit code 0 for every command, zero test failures, and both bridge/helper release binaries built.

- [ ] **Step 4: Inspect the final diff and repository state.**

Run:

```bash
git diff --stat HEAD~7..HEAD
git status --short
```

Confirm that only the persistent-helper implementation, tests, profiling, packaging, and documentation changed; no temporary helper binary, `.mcp.json`, credentials, or generated `target/` files are staged.

- [ ] **Step 5: Commit documentation and final verification changes.**

```bash
git add README.md docs/security.md docs/performance.md tests/packaging.rs .github/workflows/ci.yml
git commit -m "docs: document persistent remote helper lifecycle"
```
