# Full Architecture Release Matrix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with verification checkpoints.

**Goal:** Publish bridge packages for all common Linux targets and include every supported remote helper architecture in each package, while preserving shell fallback for incompatible GNU helper hosts.

**Architecture:** Keep the local bridge's six `uname -m` mappings explicit. Build the first three helpers as static musl artifacts and the remaining three as cross-supported GNU artifacts; package all six helper files beside every main bridge binary. The bridge continues to select a helper by exact artifact name and falls back before accepting a request when startup or execution is incompatible.

**Tech Stack:** Rust 2024, Cargo, pinned `cross` 0.2.5, GitHub Actions, shell/YAML packaging, Rust integration tests.

## Global Constraints

- No Python runtime or Python build step.
- No remote Codex, Rust, helper package, or persistent installation.
- Main release targets include x86_64, aarch64, armv7, riscv64, ppc64le, and s390x Linux.
- Helper release artifacts cover x86_64, aarch64, armv7, riscv64, ppc64le, and s390x.
- x86_64/aarch64/armv7 helpers remain musl static; riscv64/ppc64le/s390x use GNU cross targets and retain shell fallback.
- Do not force-push or move existing tags; the next release requires a new semantic version tag.

---

### Task 1: Lock the six helper mappings and release matrix in tests

**Files:**
- Modify: `tests/packaging.rs`
- Modify: `src/ssh/helper.rs` tests

**Interfaces:**
- The existing `helper_target_for_arch` test table must expect the six concrete artifact names.
- The release workflow test must require all main and helper targets, and reject no target from the approved matrix.

- [ ] **Step 1: Write the failing assertions**

Add `riscv64gc-unknown-linux-gnu`, `powerpc64le-unknown-linux-gnu`, and `s390x-unknown-linux-gnu` to the helper mapping table and require all eight main targets plus six helper targets in `tests/packaging.rs`.

- [ ] **Step 2: Run the focused tests to verify failure**

Run: `cargo test --test packaging ssh::helper 2>/dev/null || cargo test --test packaging`

Expected: FAIL because the source mapping and release workflow still use the old three-helper matrix.

- [ ] **Step 3: Commit the test-only red state**

```bash
git add tests/packaging.rs src/ssh/helper.rs
git commit -m "test: require the complete architecture release matrix"
```

### Task 2: Implement helper artifact name mappings

**Files:**
- Modify: `src/ssh/helper.rs:70-78`
- Modify: `README.md` helper compatibility section

**Interfaces:**
- `helper_target_for_arch(machine_arch: &str) -> Option<(&'static str, &'static str)>` returns GNU target names for riscv64, ppc64le, and s390x.

- [ ] **Step 1: Change only the three target strings**

Use `riscv64gc-unknown-linux-gnu`, `powerpc64le-unknown-linux-gnu`, and `s390x-unknown-linux-gnu`; leave architecture aliases and fallback behavior unchanged.

- [ ] **Step 2: Run mapping and helper tests**

Run: `cargo test helper_target_for_arch`

Expected: PASS for all six architecture rows, including armv7 alias handling.

- [ ] **Step 3: Document mixed static/dynamic helper behavior**

Update README to say all six helpers are shipped, the first three are static musl, and GNU helpers may select shell fallback when the remote loader/libc is incompatible.

- [ ] **Step 4: Commit the mapping change**

```bash
git add src/ssh/helper.rs README.md
git commit -m "feat: map all common remote architectures to helpers"
```

### Task 3: Expand GitHub Actions build and package matrices

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `tests/packaging.rs`

**Interfaces:**
- `build-main.matrix.target` contains eight approved main targets.
- `build-helper.matrix.target` contains six helper targets.
- `package.matrix.target` contains the eight main targets and installs all six helper artifact files.

- [ ] **Step 1: Add the missing target entries**

Add the three GNU main targets and three GNU helper targets to the matrices. Keep the existing musl bridge targets and first-three musl helper targets.

- [ ] **Step 2: Relax helper linkage check only for GNU helper targets**

Keep the `statically linked|musl` assertion for the three musl helper targets. For GNU helper targets, assert `file` reports an ELF executable and do not claim static linkage.

- [ ] **Step 3: Expand the package install loop**

Install all six helper files from `staging/helper-$helper/$helper` into every archive's `remote-helpers/` directory.

- [ ] **Step 4: Run packaging tests**

Run: `cargo test --test packaging`

Expected: PASS and explicit failure if a target or helper is removed from the workflow later.

- [ ] **Step 5: Commit the workflow change**

```bash
git add .github/workflows/release.yml tests/packaging.rs
git commit -m "ci: build and package all common architectures"
```

### Task 4: Version, verify, publish, and test the release

**Files:**
- Modify: `Cargo.toml`, `Cargo.lock`, `.codex-plugin/plugin.json`, `README.md`

- [ ] **Step 1: Bump the package to 0.2.4**

Update the root package, lockfile root entry, plugin manifest, and README tag example to `0.2.4`.

- [ ] **Step 2: Run local verification**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test packaging
```

Expected: all commands pass.

- [ ] **Step 3: Push main and create the immutable release tag**

Commit the version bump, push `main` over SSH 443, create `v0.2.4`, and push that tag without force.

- [ ] **Step 4: Verify GitHub Actions and release assets**

Wait for the release workflow to finish successfully. Confirm the release is non-draft/non-prerelease and each archive contains the main binary plus all six helper files.

- [ ] **Step 5: Download and install the local aarch64 package**

Download the `aarch64-unknown-linux-gnu` archive and checksum, compare SHA-256 values, install its main binary and all six helpers into a new versioned local directory, and atomically update the local `codex-ssh-bridge` link.

- [ ] **Step 6: Smoke-test the installed release**

Run MCP initialize/tools-list and a non-mutating `remote_run` against `nkai` with explicit Bash. Record the returned bridge version, actual shell, fallback flag, exit status, and elapsed time.

