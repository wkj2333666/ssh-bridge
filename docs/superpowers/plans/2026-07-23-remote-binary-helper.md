# Remote Binary Helper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a precompiled Rust helper fast path that removes the remote POSIX-shell dispatcher’s per-request temp-file/process overhead while preserving the current dispatcher as a transparent compatibility fallback.

**Architecture:** The existing local MCP bridge remains the SSH policy owner and keeps the current async `CXSB1` session reader/writer. Capability probing adds optional kernel/architecture records; a matching helper artifact is selected from `remote-helpers/`, uploaded once through a fixed shell bootstrap, and executed as the SSH session dispatcher. A separate std-only Rust helper binary parses the same bounded frames, runs each request in its own process group with concurrent stdout/stderr draining, and emits the existing result frames. Any unsupported or failed fast-path startup falls back before the first accepted request; an established helper is never silently retried through sh.

**Tech Stack:** Rust 1.91.1, standard-library helper runtime, existing Tokio bridge runtime, OpenSSH, musl release targets, GitHub Actions, Cargo integration tests.

## Global Constraints

- Keep the existing MCP tool schemas and agent-visible shell semantics unchanged.
- Keep the POSIX shell dispatcher complete and usable on every host as the fallback.
- Do not install Codex, Rust, Python, or a persistent package on a remote host.
- Do not automatically compile source code on a remote host.
- Helpers are statically linked musl binaries and are built without `target-cpu=native`.
- Supported mappings are `x86_64`, `aarch64`, `armv7l`/`armv7`, `riscv64`, `ppc64le`, and `s390x` to their matching musl targets; all other values use shell fallback.
- Helper bootstrap input is an exact byte count; uploaded bytes are never interpreted as shell text.
- Remote helper files and directories use mode `0700`; cleanup is per session.
- Preserve output limits, cancellation uncertainty, host-key policy, configured roots, shell selection, and mutation safety behavior.
- Profiling remains opt-in and is diagnostic only; cold startup and warm requests are measured separately.

---

### Task 1: Add a std-only helper wire module and conformance tests

**Files:**
- Create: `src/remote_helper_protocol.rs`
- Modify: `src/lib.rs`
- Modify: `src/ssh/frame.rs`
- Test: `tests/remote_helper.rs`

**Interfaces:**
- `codex_ssh_bridge::remote_helper_protocol::{FrameKind, Frame, read_frame, write_frame}` are synchronous, bounded std-I/O APIs used by the helper binary and local conformance tests.
- `FrameKind` tokens remain exactly the existing `CXSB1` tokens, including `READY` for shell compatibility.
- `read_frame(reader: &mut impl Read, max_payload: usize) -> io::Result<Option<Frame>>` and `write_frame(writer: &mut impl Write, frame: &Frame, max_payload: usize) -> io::Result<()>` reject malformed headers, non-ASCII headers, truncated payloads, and payloads above the bound.

- [ ] **Step 1: Write failing wire tests**

Add tests that serialize a binary payload containing NUL, newline, and `0xff`, round-trip an empty payload, reject an oversized payload, and reject a truncated payload. Add a conformance test that writes the same `HELLO_ACK` bytes through the std module and parses them with the existing async test helper.

```rust
#[test]
fn helper_wire_round_trips_binary_and_empty_payloads() {
    let frames = [
        Frame { kind: FrameKind::Stdout, request_id: 7, payload: vec![0, b'\n', 0xff] },
        Frame { kind: FrameKind::Ready, request_id: 7, payload: Vec::new() },
    ];
    let mut bytes = Vec::new();
    for frame in &frames { write_frame(&mut bytes, frame, 64).unwrap(); }
    let mut input = bytes.as_slice();
    assert_eq!(read_frame(&mut input, 64).unwrap(), Some(frames[0].clone()));
    assert_eq!(read_frame(&mut input, 64).unwrap(), Some(frames[1].clone()));
    assert_eq!(read_frame(&mut input, 64).unwrap(), None);
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run `cargo test --test remote_helper helper_wire_round_trips_binary_and_empty_payloads`; expected failure is that `remote_helper_protocol` does not yet exist.

- [ ] **Step 3: Implement the bounded std parser/writer**

Move the constants and token mapping into the new module without changing the async `src/ssh/frame.rs` API. Export the module from `src/lib.rs`; keep the async frame implementation unchanged except for tests that compare its emitted bytes with the std implementation.

- [ ] **Step 4: Run wire and regression tests**

Run `cargo test --test remote_helper --test dispatcher --lib`; expected result is all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs src/remote_helper_protocol.rs src/ssh/frame.rs tests/remote_helper.rs
git commit -m "feat: add bounded helper wire protocol"
```

### Task 2: Implement the standalone Rust helper request engine

**Files:**
- Create: `src/bin/codex-ssh-bridge-helper.rs`
- Create: `src/remote_helper.rs`
- Modify: `src/lib.rs`
- Test: `tests/remote_helper.rs`

**Interfaces:**
- `remote_helper::run(reader: impl Read, writer: impl Write, config: HelperConfig) -> io::Result<()>` owns the helper session.
- `HelperConfig { max_frame_bytes: usize, helper_version: &'static str }` validates a positive frame bound.
- The helper sends `HELLO_ACK 0` with `protocol=codex-ssh-helper/1;version=1;arch=<uname -m>;` and accepts `OPEN`, `DATA`, `CANCEL`, `HELLO`, and `CLOSE`.
- OPEN metadata is the existing `shell`, `cwd_length`, `command_length`, `stdin_length`, `login_shell`, `timeout_ms`, `stdout_limit`, and `stderr_limit` format. Unknown keys, invalid numbers, mismatched DATA lengths, and invalid shell/login paths produce request-scoped `ERROR` frames.

- [ ] **Step 1: Write failing helper integration tests**

Spawn the built helper binary with piped stdio and assert: handshake has helper protocol/version/arch fields; a `bash` or `sh` request preserves stdout, stderr, binary bytes, and exit status; two sleep requests complete concurrently; stdout and stderr limits set the EXIT truncation flags; `CANCEL` terminates the request process group; `CLOSE` exits cleanly.

```rust
#[test]
fn helper_preserves_streams_and_exit_status() {
    let mut child = helper_child();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    assert!(read_frame(&mut output).unwrap().unwrap().payload.starts_with(b"protocol=codex-ssh-helper/1;"));
    send_open_request(&mut input, 1, b"printf out; printf err >&2; exit 7");
    let result = collect_request(&mut output, 1);
    assert_eq!(result.stdout, b"out");
    assert_eq!(result.stderr, b"err");
    assert_eq!(result.exit, b"7\n0\n0\n");
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run `cargo test --test remote_helper helper_preserves_streams_and_exit_status`; expected failure is the missing helper executable/engine.

- [ ] **Step 3: Implement handshake and bounded OPEN/DATA parsing**

Use `std::io::{Read, Write}`, `std::process::Command`, `std::thread`, `std::sync::{Arc, Mutex}`, and `libc`. Read each request’s metadata and exact DATA lengths into bounded memory; reject a request whose aggregate metadata/data exceeds `max_frame_bytes` or whose IDs are duplicated. Keep a per-request cancellation entry keyed by request ID.

- [ ] **Step 4: Implement process execution and output draining**

For each accepted request, spawn a worker thread. Set the child process group with `setpgid(0, 0)` before `exec`; choose `bash --noprofile --norc -c`, `sh -c`, or the validated absolute login shell. Set `current_dir`, connect stdin, and drain stdout/stderr on separate threads. Count all bytes while retaining only the configured prefix, serialize STDOUT/STDERR/EXIT frames through one writer lock, and send EXIT as `status\nstdout_truncated\nstderr_truncated\n`. Apply timeout with a watchdog that sends TERM then KILL to the negative process-group ID. `CANCEL` uses the same termination path and reports the existing unknown-outcome semantics at the local session layer.

- [ ] **Step 5: Run helper tests and clippy**

Run `cargo test --test remote_helper --test dispatcher` and `cargo clippy --all-targets --all-features -- -D warnings`; expected result is PASS with no warnings.

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs src/remote_helper.rs src/bin/codex-ssh-bridge-helper.rs tests/remote_helper.rs
git commit -m "feat: add standalone remote helper executor"
```

### Task 3: Extend capability probing with optional kernel and architecture data

**Files:**
- Modify: `src/capability.rs`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/real_ssh.rs`
- Modify: `tests/remote_ops.rs`

**Interfaces:**
- `Capability.kernel_name: Option<String>` and `Capability.machine_arch: Option<String>` are bounded optional records. Missing records preserve compatibility with old test fixtures and force the shell path.
- `parse_probe_output` accepts `KERNEL_NAME` and `MACHINE_ARCH`, validates printable ASCII and maximum lengths, and retains all existing required-record checks.
- The probe emits `KERNEL_NAME=$(uname -s)` and `MACHINE_ARCH=$(uname -m)` using the existing safe `emit_record` path.

- [ ] **Step 1: Add parser tests before implementation**

Add tests for valid `Linux`/`x86_64`, unsupported/empty architecture, overlong values, duplicate fields, and old output without the optional records. Assert old output still parses and `machine_arch == None`.

- [ ] **Step 2: Run capability tests and verify new tests fail**

Run `cargo test --lib capability:: tests::ssh_transport` (or the two exact test filters if Cargo rejects the combined filter); expected failures are missing fields/accessors.

- [ ] **Step 3: Implement optional records and fixture updates**

Add the two records to `CAPABILITY_PROBE_SCRIPT`, add bounded constants, parse the optional values, and update test constructors only where a helper-path test needs `Some("Linux")` and `Some("x86_64")`.

- [ ] **Step 4: Run all capability/transport regressions**

Run `cargo test --lib capability:: --test ssh_transport --test real_ssh --test remote_ops`; expected result is PASS.

- [ ] **Step 5: Commit**

```bash
git add src/capability.rs tests/ssh_transport.rs tests/real_ssh.rs tests/remote_ops.rs
git commit -m "feat: probe remote kernel architecture"
```

### Task 4: Add artifact mapping, secure bootstrap, and startup fallback

**Files:**
- Create: `src/ssh/helper.rs`
- Modify: `src/ssh/mod.rs`
- Modify: `src/ssh/dispatcher.rs`
- Modify: `src/ssh/session.rs`
- Test: `tests/remote_helper.rs`

**Interfaces:**
- `HelperArtifact { path: PathBuf, target: &'static str, arch: &'static str }` is returned by `helper_artifact(capability: &Capability) -> Option<HelperArtifact>`.
- `helper_directory()` honors `CODEX_SSH_BRIDGE_HELPERS_DIR`; otherwise it resolves `remote-helpers/` next to the current bridge executable. It accepts only regular executable files owned by the current user or root and rejects symlinks, group/other-writable directories, and unexpected filenames.
- `helper_command(artifact: &HelperArtifact, max_frame_bytes: usize, helper_len: u64) -> BridgeResult<String>` returns a fixed shell-quoted bootstrap that creates a private `mktemp`-style directory, reads exactly `helper_len` bytes, verifies the count, chmods `0700`, and `exec`s the helper with `--max-frame`.
- `HostSession::connect_with(..., capability: &Capability, ...)` tries the helper only before creating a request-capable session, validates helper handshake fields, and then falls back to `dispatcher_command` on missing artifact, non-Linux/unsupported architecture, bootstrap/exec failure, EOF, or protocol mismatch.

- [ ] **Step 1: Add failing mapping/bootstrap tests**

Test every supported mapping, an unknown architecture, non-Linux, missing artifact, shell-quote metacharacters in paths, exact upload length, and rejection of a helper artifact with unsafe permissions. Add a fake-SSH startup test that emits helper handshake, then assert `HostSession` selects helper; add one that emits EOF and assert shell fallback is attempted once.

- [ ] **Step 2: Run focused tests and verify failure**

Run `cargo test --test remote_helper helper_`; expected failure is missing mapping/bootstrap/session integration.

- [ ] **Step 3: Implement secure artifact discovery and bootstrap**

Use `std::fs::symlink_metadata`, mode/owner checks, `shell_word`, and a fixed script containing no interpolation of uploaded bytes. Stream the artifact exactly once through the SSH child stdin before normal protocol frames; keep the bootstrap’s input framing separate from `CXSB1` and never retry after the first request frame is written.

- [ ] **Step 4: Implement helper handshake validation and fallback**

Accept either `protocol=codex-ssh-dispatcher/1` or `protocol=codex-ssh-helper/1`. For the helper require version `1`, bounded `arch`, and an architecture equal to the probed value. Record the selected path in debug/profile diagnostics. On pre-accept failure, kill/wait the SSH child and run the existing shell dispatcher connection path exactly once.

- [ ] **Step 5: Run focused and session regressions**

Run `cargo test --test remote_helper --test dispatcher --test session --test ssh_transport`; expected result is PASS, including existing READY-frame compatibility.

- [ ] **Step 6: Commit**

```bash
git add src/ssh/helper.rs src/ssh/mod.rs src/ssh/dispatcher.rs src/ssh/session.rs tests/remote_helper.rs
git commit -m "feat: select remote helper with shell fallback"
```

### Task 5: Integrate helper selection into the runner without changing MCP behavior

**Files:**
- Modify: `src/ssh/process.rs`
- Modify: `src/ssh/session.rs`
- Modify: `src/profile.rs`
- Modify: `tests/session.rs`
- Modify: `tests/ssh_transport.rs`

**Interfaces:**
- `SshRunner::session_for_host` passes the already-probed `Capability` into session creation, avoiding a second SSH probe/round trip.
- `SessionInner.transport_kind` is either `Dispatcher` or `Helper` for diagnostics only; request/result schemas remain unchanged.
- Profile events use `helper_bootstrap`, `helper_frame_write`, `helper_command_spawn`, `helper_output_drain`, and `helper_exit`; shell paths retain existing phase names.

- [ ] **Step 1: Add integration assertions before implementation**

Extend the fake SSH fixture to record the command used for helper bootstrap and assert a warm helper request has no `READY` dependency, preserves Bash default selection, and returns the same `RunResult` as the shell fixture. Assert an unknown architecture reports shell fallback in diagnostics and still succeeds.

- [ ] **Step 2: Run runner tests and verify failure**

Run `cargo test --test session --test ssh_transport`; expected failure is the missing capability argument/transport kind/helper selection.

- [ ] **Step 3: Thread capability into session creation**

Change only the internal `session_for_host`/`HostSession::connect_with` signatures; use the cached `Arc<Capability>` from `initialize_host`. Do not add any new capability probe or per-request SSH process.

- [ ] **Step 4: Preserve cancellation, limits, and result handling**

Keep the existing local pending-request map, output sink streaming, aggregate limits, timeout/cancel grace, and unknown-outcome transport errors. The only helper-specific change in the local reader is accepting the helper handshake and treating omitted READY as normal.

- [ ] **Step 5: Run full Rust tests and clippy**

Run `cargo test --all-targets --all-features` and `cargo clippy --all-targets --all-features -- -D warnings`; expected result is PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ssh/process.rs src/ssh/session.rs src/profile.rs tests/session.rs tests/ssh_transport.rs
git commit -m "perf: use helper sessions without changing runner semantics"
```

### Task 6: Package main binary and all helper artifacts in release CI

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `tests/packaging.rs`
- Modify: `README.md`
- Modify: `docs/security.md`
- Modify: `docs/performance.md`

**Interfaces:**
- Release archives contain the main target binary and `remote-helpers/<helper-target>` files; archives remain independently checksummed.
- Main release targets stay `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf`, `x86_64-unknown-linux-musl`, and `aarch64-unknown-linux-musl`.
- Helper build matrix adds `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf`, `riscv64gc-unknown-linux-musl`, `powerpc64le-unknown-linux-musl`, and `s390x-unknown-linux-musl`.

- [ ] **Step 1: Add packaging assertions**

Test that a release layout contains the main binary plus exactly the six helper target names, helper files are executable, and no Python/bin legacy artifact is reintroduced. Add a static-link check using `file`/`ldd` when available, with a clear skip on platforms without those tools.

- [ ] **Step 2: Run packaging tests and verify failure**

Run `cargo test --test packaging`; expected failure is the missing `remote-helpers` layout/documentation.

- [ ] **Step 3: Update the workflow**

Build the main binary once per existing main target and helper binary once per helper target with the pinned Rust toolchain/cross version. Assemble one archive per main target containing `codex-ssh-bridge` and all helper artifacts, generate SHA-256 files, and retain the existing tag/version check and GitHub release publication.

- [ ] **Step 4: Document installation and fallback**

Explain that users download the archive, keep `remote-helpers/` beside the bridge binary, and that unsupported/new servers automatically use the shell dispatcher. Document `CODEX_SSH_BRIDGE_HELPERS_DIR`, no remote installation, helper upload/cleanup, and the security/performance tradeoff.

- [ ] **Step 5: Run package and documentation checks**

Run `cargo test --test packaging`; run `git diff --check`; expected result is PASS with no whitespace errors.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/release.yml tests/packaging.rs README.md docs/security.md docs/performance.md
git commit -m "ci: package static remote helper artifacts"
```

### Task 7: Verify cold/warm performance and compatibility acceptance

**Files:**
- Modify: `tests/performance_acceptance.rs`
- Modify: `tests/real_ssh.rs`
- Modify: `docs/performance.md`

**Interfaces:**
- Acceptance output reports separate `helper_cold`, `helper_warm`, `shell_cold`, and `shell_warm` timings plus profile phases; it never treats profile-enabled timings as a hard latency gate.

- [ ] **Step 1: Add the acceptance test shape**

Add a release-only test that runs one cold helper request, at least five warm helper requests, then repeats against a forced shell fallback on the same fixture. Assert output/status equivalence and print median/p95 wall-clock values plus the bridge profile JSONL path.

- [ ] **Step 2: Run the acceptance test locally**

Run `cargo test --release --test performance_acceptance task12_helper_cold_and_warm -- --nocapture`; when no real SSH fixture is configured, the test must print the explicit release-only skip instead of failing.

- [ ] **Step 3: Run the complete verification suite**

Run `cargo fmt --all -- --check`, `cargo test --all-targets --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`, and `git diff --check`. Expected result: all commands succeed; any unavailable release cross target is reported by CI rather than hidden locally.

- [ ] **Step 4: Commit verification/docs**

```bash
git add tests/performance_acceptance.rs tests/real_ssh.rs docs/performance.md
git commit -m "test: compare helper and shell cold warm latency"
```

