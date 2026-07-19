# Final Review Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the final review gaps by making the resolved OpenSSH target identity immutable for a bridge process, forcing operational keepalives, requiring a non-skipped real-SSH release gate, and rejecting unknown configuration versions.

**Architecture:** Continue delegating connection semantics to system OpenSSH, but re-run bounded `ssh -G` before every operation and compare its digest with the alias's immutable first digest before building or using a ControlMaster policy. Share compiled server-alive constants across `ssh -G`, operational SSH, and SSHFS. Keep ordinary developer real-SSH tests skippable, while an explicit release environment flag converts setup unavailability into failure.

**Tech Stack:** Rust 1.91.1, Tokio, system OpenSSH, existing fake-SSH and localhost-sshd fixtures.

## Global Constraints

- The runtime, installer, benchmarks, and test fixtures must not use Python.
- System `/usr/bin/ssh` remains the protocol implementation so `Include`, `Match`, `ProxyJump`, ssh-agent, hardware keys, and configured `ProxyCommand` remain supported.
- Remote hosts receive no installed binary, daemon, Codex credential, or persistent helper.
- The first resolved connection identity and first remote root identity are immutable for the lifetime of one bridge process.
- Every operational and `ssh -G` invocation forces `ServerAliveInterval=15` and `ServerAliveCountMax=3` in addition to the existing hardening and configured `ConnectTimeout`.
- Ordinary developer runs may visibly skip unavailable localhost `sshd`; release acceptance with `CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1` must fail instead of skip.
- Configuration format version is exactly `1`; all other values fail closed.
- Existing latency, cancellation, memory, wire-size, and five-host gates must not be weakened.

---

### Task 1: Resolve Final Security and Acceptance Findings

**Files:**

- Modify: `src/ssh/process.rs`
- Modify: `src/ssh/mod.rs`
- Modify: `src/ssh/argv.rs`
- Modify: `src/config.rs`
- Modify: `tests/fixtures/fake-ssh.sh`
- Modify: `tests/ssh_transport.rs`
- Modify: `tests/core.rs`
- Modify: `tests/real_ssh.rs`
- Modify: `tests/cli.rs`
- Modify: `README.md`
- Modify: `docs/security.md`
- Modify: `docs/performance.md`
- Modify: `docs/superpowers/specs/2026-07-18-codex-ssh-bridge-rust-design.md`
- Modify: `docs/superpowers/plans/2026-07-18-codex-ssh-bridge-rust.md`
- Rebuild: `bin/codex-ssh-bridge`

**Interfaces:**

- `SshRunner::initialize_host` resolves the current identity on every call, inserts the first digest once, and returns `INVALID_CONFIG` before probe/root observation/command when a later digest differs.
- `SERVER_ALIVE_INTERVAL_SECONDS` is `15` and `SERVER_ALIVE_COUNT_MAX` is `3`; one shared helper produces the two OpenSSH option values used by policy construction and `ssh -G`.
- `CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1` makes localhost fixture setup failure panic with the setup reason; absence of the flag retains the visible developer skip.
- `Config::validate` accepts only `version == 1`.

- [x] **Step 1: Write failing OpenSSH identity-drift and keepalive tests**

Add a fake-SSH identity file input so a test can replace the `ssh -G` output between two operations without changing the fake remote root/device/inode. Change the former resolve-once expectation to two `G` calls for two operations. Add a regression that performs one successful call, changes only the resolved configuration text, then proves the second call returns `INVALID_CONFIG` before another `P`, `R`, or `C` call. Assert `ServerAliveInterval=15` and `ServerAliveCountMax=3` occur exactly once in bootstrap `ssh -G`, cold operational, cached operational, and SSHFS argv.

- [x] **Step 2: Run the transport tests and verify RED**

Run:

```bash
cargo test --test ssh_transport runner_revalidates -- --nocapture
cargo test --test ssh_transport resolved_identity_drift -- --nocapture
cargo test --test ssh_transport argv_uses_hardened -- --nocapture
cargo test --test cli sshfs_argv -- --nocapture
```

Expected: the first two tests fail because identity is resolved once; keepalive assertions fail because ordinary policy and `ssh -G` omit the two options.

- [x] **Step 3: Implement immutable connection-identity revalidation and shared keepalives**

Resolve a digest before every `initialize_host`. Under the identity mutex, insert only when absent; when present, compare in constant ordinary string equality and return a non-retryable invalid-configuration error instructing the operator to verify the alias and restart the bridge. Never replace the cached digest. Build the ControlPath only from that immutable digest. Put the two compiled numeric constants and one option helper in `src/ssh/mod.rs`; consume it from `SshPolicy::for_host` and `resolve_identity_once`. Remove duplicate SSHFS-only keepalive insertion because SSHFS inherits the policy.

- [x] **Step 4: Run transport/CLI tests and verify GREEN**

Run:

```bash
cargo test --test ssh_transport -- --test-threads=1
cargo test --test cli -- --test-threads=1
```

Expected: all tests pass with two `G` calls for two operations, drift rejection before business execution, and exactly one copy of each server-alive option.

- [x] **Step 5: Write failing configuration-version and required-real-SSH tests**

Add core cases for loading and saving `version = 0` and `version = 2`, both expecting `INVALID_CONFIG`. Factor the real-SSH setup decision into a small helper and add tests proving unavailable setup returns `None` only when `required=false`, while `required=true` panics/fails with the original reason. The integration test obtains `required` only from the exact value `CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1`.

- [x] **Step 6: Run focused tests and verify RED**

Run:

```bash
cargo test --test core config_rejects_unsupported_version -- --nocapture
cargo test --test real_ssh required_mode -- --nocapture
```

Expected: version cases fail because `Config::validate` ignores `version`; required-mode cases fail because setup failure always returns successfully.

- [x] **Step 7: Implement exact config version and required acceptance mode**

Add one `CONFIG_VERSION: u32 = 1` constant and reject any other value in `Config::validate` before limits or hosts are interpreted. In `tests/real_ssh.rs`, preserve visible skip output for developer mode but panic with `required real SSH integration unavailable: <reason>` in required mode.

- [x] **Step 8: Run focused tests and verify GREEN**

Run:

```bash
cargo test --test core config_rejects_unsupported_version -- --nocapture
cargo test --test real_ssh required_mode -- --nocapture
CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1 cargo test --release --test real_ssh -- --nocapture
```

Expected: focused tests pass; the required real-SSH command executes one localhost fixture with one pass, zero failures, and no skip.

- [x] **Step 9: Align documentation and completion records**

Document that every operation re-resolves and compares the immutable connection identity, that the same-UID/local SSH configuration remains trusted and an exact post-check race is inside that boundary, and that both server-alive options apply to normal SSH as well as SSHFS. Record the required real-SSH command. Mark the original plan's completed checkboxes and add dated final-review evidence without changing any threshold.

- [x] **Step 10: Run complete verification and rebuild the package**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features -- --test-threads=1
cargo test --release --test performance_acceptance -- --nocapture
CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1 cargo test --release --test real_ssh -- --nocapture
cargo build --release
```

Copy `target/release/codex-ssh-bridge` to `bin/codex-ssh-bridge`, keep mode `0755`, and verify their SHA-256 values match. Expected: all commands exit zero; required real SSH does not print `SKIP`; all performance thresholds remain unchanged and pass.

- [x] **Step 11: Commit**

```bash
git add src tests README.md docs bin
git commit -m "fix: pin OpenSSH identity across remote operations"
```

## Final Evidence — 2026-07-19

- All 11 steps above are complete.
- The controller ran `CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1 cargo test --release --test real_ssh -- --nocapture` outside the bind-restricted sandbox: 3 passed, 0 failed, 0 ignored, and the localhost integration emitted no `SKIP`.
- Final release and packaged binaries match at SHA-256 `d75c745b756d381dcf1266ce34fb3201dafb5898ed20b9ad413d45365c4d298a`; `bin/codex-ssh-bridge` remains mode `0755`.
