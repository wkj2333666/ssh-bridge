# GitHub Actions Cache Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split GitHub Actions caches by resource type, add shared Rust/cross tool caches, remove obsolete cache entries, and verify the repository stays below the cache budget.

**Architecture:** CI and release jobs will use four independent cache layers: pinned Rust toolchain, shared Cargo dependencies, role/target-specific `target`, and versioned `cross` binary. Existing combined caches are not compatible with the new keys and will be deleted after the workflow change is pushed.

**Tech Stack:** GitHub Actions, `actions/cache@v4.3.0`, Rust `1.91.1`, `cross 0.2.5`, `gh cache`.

## Global Constraints

- Do not run local Cargo build, check, test, or release commands.
- Keep Rust toolchain pinned to `1.91.1` and `cross` pinned to `0.2.5`.
- Keep all release targets and artifact layout unchanged.
- Cache only Ubuntu runner resources; do not cache apt/ripgrep.
- Delete only validated obsolete GitHub Actions cache IDs.

---

### Task 1: Split CI caches and add the shared Rust toolchain cache

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `RUST_TOOLCHAIN` and `Cargo.lock`.
- Produces: shared keys `Linux-x64-rust-toolchain-1.91.1-minimal`, `Linux-rust-deps-1.91.1-<lock>`, and CI target key `Linux-rust-target-1.91.1-<lock>`.

- [ ] **Step 1: Add the toolchain cache before pinned installation**

For both `quality` and `diagnostics`, add an `actions/cache` step before
`rustup toolchain install`:

```yaml
- name: Restore pinned Rust toolchain cache
  uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
  with:
    path: ~/.rustup/toolchains/${{ env.RUST_TOOLCHAIN }}-*
    key: ${{ runner.os }}-${{ runner.arch }}-rust-toolchain-${{ env.RUST_TOOLCHAIN }}-minimal
```

- [ ] **Step 2: Replace the combined CI cache with dependency and target caches**

Use one dependency cache and one target cache in each job:

```yaml
- name: Restore shared Cargo dependency cache
  uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
  with:
    path: |
      ~/.cargo/registry
      ~/.cargo/git
    key: ${{ runner.os }}-rust-deps-${{ env.RUST_TOOLCHAIN }}-${{ hashFiles('Cargo.lock') }}
    restore-keys: |
      ${{ runner.os }}-rust-deps-${{ env.RUST_TOOLCHAIN }}-

- name: Restore CI target cache
  uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
  with:
    path: target
    key: ${{ runner.os }}-rust-target-${{ env.RUST_TOOLCHAIN }}-${{ hashFiles('Cargo.lock') }}
    restore-keys: |
      ${{ runner.os }}-rust-target-${{ env.RUST_TOOLCHAIN }}-
```

- [ ] **Step 3: Keep quality components explicit**

Retain `rustup component add rustfmt clippy --toolchain "$RUST_TOOLCHAIN"` in
`quality`; do not rely on the toolchain cache to decide whether those components
are present.

- [ ] **Step 4: Run non-build local validation**

Run `git diff --check` and inspect the workflow diff. Do not run Cargo locally.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: split dependency and toolchain caches"
```

### Task 2: Split release caches and cache `cross`

**Files:**
- Modify: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `RUST_TOOLCHAIN`, `CROSS_VERSION`, `Cargo.lock`, and each matrix target.
- Produces: shared release dependency/toolchain/cross caches and target-only bridge/helper caches.

- [ ] **Step 1: Add the shared Rust toolchain cache before installation**

In both `build-main` and `build-helper`, add:

```yaml
- name: Restore pinned Rust toolchain cache
  uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
  with:
    path: ~/.rustup/toolchains/${{ env.RUST_TOOLCHAIN }}-*
    key: ${{ runner.os }}-${{ runner.arch }}-rust-toolchain-${{ env.RUST_TOOLCHAIN }}-minimal
```

- [ ] **Step 2: Replace bridge/helper combined caches**

Each build job must use the shared dependency cache:

```yaml
- name: Restore shared Cargo dependency cache
  uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
  with:
    path: |
      ~/.cargo/registry
      ~/.cargo/git
    key: ${{ runner.os }}-rust-deps-${{ env.RUST_TOOLCHAIN }}-${{ hashFiles('Cargo.lock') }}
    restore-keys: |
      ${{ runner.os }}-rust-deps-${{ env.RUST_TOOLCHAIN }}-
```

The bridge target cache must use `path: target` and key
`${{ runner.os }}-rust-target-${{ env.RUST_TOOLCHAIN }}-bridge-${{ matrix.target }}-${{ hashFiles('Cargo.lock') }}`.
The helper target cache must use `path: target` and key
`${{ runner.os }}-rust-target-${{ env.RUST_TOOLCHAIN }}-helper-${{ matrix.target }}-${{ hashFiles('Cargo.lock') }}`.
Both restore keys must end at the role and target prefix.

- [ ] **Step 3: Add a versioned `cross` binary cache**

Before installation, add:

```yaml
- name: Restore cross binary cache
  id: cross-cache
  uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4.3.0
  with:
    path: ~/.cargo/bin/cross
    key: ${{ runner.os }}-${{ runner.arch }}-cross-${{ env.RUST_TOOLCHAIN }}-${{ env.CROSS_VERSION }}

- name: Install pinned cross compiler
  if: steps.cross-cache.outputs.cache-hit != 'true'
  run: cargo +"$RUST_TOOLCHAIN" install cross --version "$CROSS_VERSION" --locked

- name: Verify cross compiler
  run: test -x "$HOME/.cargo/bin/cross" && "$HOME/.cargo/bin/cross" --version
```

Remove the old unconditional `cargo install cross` step.

- [ ] **Step 4: Run non-build local validation**

Run `git diff --check` and inspect that artifact paths, target matrices, and
release packaging are unchanged. Do not run Cargo locally.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: cache Rust toolchain and cross binary"
```

### Task 3: Push, remove obsolete remote caches, and run GitHub verification

**Files:**
- No source files; GitHub Actions cache state and run metadata only.

**Interfaces:**
- Consumes: explicit cache IDs from `gh cache list --repo wkj2333666/Codex-SSH-Bridge`.
- Produces: fresh cache entries for the new keys and a measured total size.

- [ ] **Step 1: Push workflow commits**

Run `git push origin main`. Confirm the pushed revision is the current local
`main` and that a new CI run is created.

- [ ] **Step 2: Enumerate obsolete cache IDs**

Run `gh cache list --repo wkj2333666/Codex-SSH-Bridge --limit 100 --json id,key,sizeInBytes`.
Keep only entries whose keys begin with the new `Linux-x64-rust-toolchain-`,
`Linux-rust-deps-`, `Linux-rust-target-`, or `Linux-x64-cross-` prefixes and whose
lock hash is current. Delete every old cache by its explicitly listed numeric ID
using `gh cache delete <id> --repo wkj2333666/Codex-SSH-Bridge --confirm`.

- [ ] **Step 3: Wait for GitHub verification**

Use `gh run watch <run-id> --repo wkj2333666/Codex-SSH-Bridge --exit-status`.
The quality, diagnostics, release build-main, and build-helper jobs must pass.

- [ ] **Step 4: Measure cache usage and hits**

Run `gh cache list --repo wkj2333666/Codex-SSH-Bridge --limit 100 --json key,sizeInBytes,lastAccessedAt` and sum `sizeInBytes` with `jq`. Confirm the total is below 10 GB and logs show hits for the toolchain, dependency, and cross caches on a subsequent eligible run.

- [ ] **Step 5: Commit any workflow corrections**

If GitHub reports a workflow error, fix only the workflow, run `git diff --check`,
commit the correction, and repeat the CI verification. Do not run local Cargo
builds or tests.
