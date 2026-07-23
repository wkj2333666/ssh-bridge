# SSH Bridge Profile, Memory, and CI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate cold and warm SSH timing, add opt-in Rust profiling, remove avoidable output RSS amplification, and make GitHub CI/release the normal build path for Raspberry Pi users.

**Architecture:** A compile-time `profile` Cargo feature provides an environment-gated stderr JSONL recorder. Existing runner timing boundaries are instrumented without changing MCP wire responses. Remote output capture consumes the session result instead of cloning it, while fresh-child RSS tests cover framing, admission, session capture, output storage, and retained models. CI runs host tests plus release diagnostics; the existing cross-target release workflow remains the artifact producer.

**Tech Stack:** Rust 2024, Tokio, existing `serde_json`, Cargo features, GitHub Actions, and the existing POSIX fake-SSH fixture. No Python, no new runtime dependency, no SSHFS, and no remote Codex installation.

## Global Constraints

- Normal release builds compile profile instrumentation out.
- `CODEX_SSH_BRIDGE_PROFILE=1` is required to emit profile lines, only on stderr.
- Profile fields may contain phase, request id, host alias, cold/warm class, elapsed microseconds, and byte counts; never commands, paths, output, stdin, credentials, or SSH argv.
- Cold-start and warm-request measurements are separate; no `<10 ms` full-SSH assertion.
- Memory ceilings remain independent of latency ceilings and are not weakened.
- Worktrees remain project-local under ignored `.worktrees/`.
- CI builds and publishes the bridge; Raspberry Pi users download and checksum a release binary.

---

### Task 1: Isolated baseline

**Files:** none. **Test:** repository-wide Cargo tests.

- [ ] Confirm `git worktree list` shows `.worktrees/performance-profile-memory-ci` on `codex/performance-profile-memory-ci`, and `git status --short --branch` is clean.
- [ ] Run `cargo test --locked --all-targets --all-features -- --test-threads=1`.
- [ ] Record any pre-existing failure before changing production code.

---

### Task 2: Profile API (test first)

**Files:** modify `Cargo.toml` and `src/lib.rs`; create `src/profile.rs`; test `src/profile.rs`.

**Interface:** `bridge_profile!`, `bridge_profile_span!`, `ProfileSpan::new(phase, fields)`, and `ProfileConfig::enabled()` are available inside the crate. The no-feature implementation is a no-op.

- [ ] Add a failing unit test that renders a safe event containing phase `warm_session`, host `dev`, request id `7`, class `warm`, elapsed `1234`, and bytes `64`, and asserts that command/path/output fields are absent. Run `cargo test --locked profile::tests::profile_event_contains_only_safe_fields`; it must fail because the module does not exist.
- [ ] Add Cargo feature `profile = []` and `pub mod profile;`.
- [ ] Implement feature-gated JSONL rendering with `OnceLock<bool>` for `CODEX_SSH_BRIDGE_PROFILE=1`, a short stderr write mutex, and an RAII `ProfileSpan` that emits on drop. Implement no-feature macros/span methods with no environment lookup or formatting.
- [ ] Run `cargo test --locked profile::tests` and `cargo test --locked --no-default-features profile::tests`; both must pass.
- [ ] Commit with `git add Cargo.toml src/lib.rs src/profile.rs && git commit -m "feat: add opt-in bridge profiling"`.

---

### Task 3: Cold/warm phase instrumentation (test first)

**Files:** modify `src/mcp/mod.rs`, `src/ssh/process.rs`, `src/ssh/session.rs`, `src/output.rs`, and `tests/performance_acceptance.rs`; rename/remove the stale full-call test in `tests/mcp_tools.rs`.

**Interface:** Existing `RunTiming` remains internal and MCP responses remain unchanged. Profile phases are `mcp_admission`, `runner_preparation`, `session_connect`, `session_request`, `output_capture`, and `mcp_render`.

- [ ] Add release-only test `task11_release_cold_and_warm_ssh_profile`: one fresh fixture cold call, then at least 100 calls on the same fixture; print separate cold/warm p50/p95/max; assert one `G`, one `P`, zero `R`, and one `C` per command. Run `cargo test --release --locked --test performance_acceptance task11_release_cold_and_warm_ssh_profile -- --nocapture`; it must fail because the new report/profile events are absent.
- [ ] Add spans at existing preparation/session/capture boundaries, plus session connect and frame send/wait, MCP admission/queue/render, and OutputStore capture/spool. Do not add timing fields to the MCP wire response.
- [ ] Run `CODEX_SSH_BRIDGE_PROFILE=1 cargo test --release --locked --features profile --test performance_acceptance task11_release_cold_and_warm_ssh_profile -- --nocapture`; it must pass and show no repeated warm setup markers.
- [ ] Rename `task78_release_fake_call_p95_is_below_ten_milliseconds` to a report-only cold/warm test or delete it in favor of the new acceptance test. Keep the bridge-only `<2 ms` gate and broad complete-call regression ceiling.
- [ ] Commit with `git add src/mcp/mod.rs src/ssh/process.rs src/ssh/session.rs src/output.rs tests/performance_acceptance.rs tests/mcp_tools.rs && git commit -m "perf: separate cold and warm bridge timings"`.

---

### Task 4: Resource RSS audit and output fix (test first)

**Files:** modify `src/ssh/process.rs`; modify `src/output.rs` only if the audit finds another resident duplicate; extend `tests/mcp_tools.rs`, `tests/performance_acceptance.rs`, and `tests/mcp_protocol.rs`.

**Interface:** `remote_run` capture consumes `SessionResult`; `CapturedOutput`, `OutputStore`, paging, provenance, and MCP wire schemas remain unchanged.

- [ ] Run `cargo test --release --locked --test mcp_tools task8_output_rss_64_mib_and_retained_models_stay_below_sixteen_mib -- --nocapture`; before the fix it must report roughly 138 MiB peak delta and fail the 16 MiB ceiling.
- [ ] Add fresh-child markers for wide JSON frame, Base64 admission, session output capture, OutputStore paging/retention, and retained MCP models; keep each existing ceiling and real code path.
- [ ] Change `capture_session_output` to consume the result, reusing the existing move-based capture implementation. Preserve output-limit and cancellation context before moving the result.
- [ ] Run `cargo test --release --locked --test mcp_tools task8_output_rss_ -- --nocapture`, `cargo test --release --locked --test performance_acceptance task11_release_bounded_session_output_rss_fresh_child -- --nocapture`, and `cargo test --release --locked --test mcp_protocol task7_wide_json_rss_ -- --nocapture`.
- [ ] If session output still exceeds its ceiling, stop and redesign frame receipt to stream directly into OutputStore; do not weaken the RSS test.
- [ ] Commit with `git add src/ssh/process.rs src/output.rs tests/mcp_tools.rs tests/performance_acceptance.rs tests/mcp_protocol.rs && git commit -m "perf: remove remote output capture amplification"`.

---

### Task 5: GitHub CI and release diagnostics

**Files:** modify `.github/workflows/ci.yml`, `.github/workflows/release.yml` only if needed, `README.md`, and `docs/performance.md`.

- [ ] Add a CI profile job using the pinned Rust toolchain, `cargo build --release --features profile`, `CODEX_SSH_BRIDGE_PROFILE=1`, the cold/warm acceptance test, and `actions/upload-artifact` pinned to the existing SHA. Upload `profile.jsonl` and test output.
- [ ] Add a release-only RSS job and upload raw RSS output. RSS failures remain hard failures; hosted-runner latency is diagnostic rather than a strict network SLA.
- [ ] Retain the existing five-target matrix, tag/version equality, tarball names, and SHA-256 files; never publish profile binaries.
- [ ] Document that 64-bit Pi uses `aarch64-unknown-linux-gnu`, 32-bit Pi uses `armv7-unknown-linux-gnueabihf`, release checksums are required, and hosted CI cannot measure real Pi-to-server network latency.
- [ ] Commit with `git add .github/workflows/ci.yml .github/workflows/release.yml README.md docs/performance.md && git commit -m "ci: publish profile and resource diagnostics"`.

---

### Task 6: Verification and handoff

**Files:** none unless verification finds a concrete issue.

- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --all-targets --all-features --locked -- -D warnings`.
- [ ] Run `cargo test --all-targets --all-features --locked -- --test-threads=1`.
- [ ] Run `CODEX_SSH_BRIDGE_PROFILE=1 cargo test --release --features profile --locked --test performance_acceptance -- --nocapture`.
- [ ] Run release RSS tests for `mcp_tools`, `performance_acceptance`, and `mcp_protocol`.
- [ ] Run `cargo build --release --locked` without `profile`.
- [ ] Review `git status --short --branch`, `git diff main...HEAD --stat`, and `git worktree list`; keep `main` unchanged and wait for the user to choose merge/push.
