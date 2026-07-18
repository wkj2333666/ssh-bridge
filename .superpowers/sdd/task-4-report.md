# Task 4 High-Level Remote Read Report

Date: 2026-07-18

## Outcome

Implemented the Rust-only high-level remote read facade: hosts, list, stat,
read, literal rg/grep search, and provenanced output paging. All remote process
launches remain owned by `SshRunner`; `src/remote` launches no process.

## Files

- Dependencies/errors/exports: `Cargo.toml`, `Cargo.lock`, `src/error.rs`,
  `src/lib.rs`
- Transport/capture/capabilities: `src/capability.rs`, `src/output.rs`,
  `src/ssh/mod.rs`, `src/ssh/process.rs`
- Facade/protocols: `src/remote/mod.rs`, `src/remote/protocol.rs`,
  `src/remote/metadata.rs`, `src/remote/read.rs`, `src/remote/search.rs`
- Tests/fixture: `tests/remote_ops.rs`, `tests/ssh_transport.rs`,
  `tests/fixtures/fake-ssh.sh`
- Design/plan: the two Task 4 documents under `docs/superpowers/`.

## TDD Evidence

- Initial public-shape RED: compilation failed because `remote` and
  `ErrorCode::ReadConflict` did not exist. The exact serde/type test then passed.
- Fixed-runner RED: missing `render_fixed_command` and `InternalSpoolOwner`.
  Renderer, forced internal capture, weak registration, late-registration
  cleanup, and facade-abort cleanup tests then passed.
- Capability RED: the old ten-key probe assertion rejected the seven new
  functional keys. The functional probe test now asserts all seven true and
  verifies scratch cleanup.
- Search cap debugging produced three meaningful REDs: an over-conservative
  argv reserve, planned SIGPIPE classified as an engine error, and utility
  stderr entering control framing. Each cause was fixed and its regression test
  is green.
- Five-host peak test initially expected `ProtocolError`; it demonstrated the
  stronger correct behavior, `OutputLimit` with no partial result. Its corrected
  assertion passed twice consecutively.

## Bounds and Security Review

- Input paths 64 KiB; stat 256 paths; read 32 paths; list depth 32 and 10,000
  entries; search 10,000 results/128 globs; query 64 KiB; read aggregate 1 MiB;
  protocol frame 8 MiB plus exactly one planned lookahead byte.
- Whole request and fixed command/stdin sizes use checked arithmetic before
  process launch. Stat operands and discovered candidates use NUL stdin and
  sequential `xargs -0`, not a caller-controlled command line.
- All fixed scripts are `&'static str`; caller values are quoted once as
  positional operands. Non-UTF-8 discovered paths never enter `shell_word`.
- Internal captures always use private mode-0600 files, never public tokens.
  A facade-entry strong owner and capture-side weak registration remove paths
  on success, error, cancellation, late registration, and task abort. TTL is
  not the ordinary cleanup path.
- Search uses mode-0700 `mktemp` scratch, trapped FIFO cleanup, foreground
  `head -c remaining+1`, separate producer/engine status files, suppressed
  utility diagnostics, and no `pipefail`. A hard `OutputLimit` is never partial
  success.
- Capability retry accepts only the exact exit-zero NUL record naming a key in
  the operation's static required set, invalidates/reprobes once, and rejects an
  unknown key as `ProtocolError`.
- Fixed error strings never include remote stderr or untrusted path bytes.
- Roots are lexical operational guards, not confinement: a final read symlink
  may intentionally reach outside the configured root.

## Adversarial Evidence

- Exact 8 MiB + 1 frame keeps only complete record groups.
- 10,001 metadata entries return 10,000 with `truncated=true`; FIFO, Unix
  socket, permission denial, and pre-epoch timestamp paths were exercised.
- A deterministic 128 MiB hash-before/hash-after mutation returns a contentless
  `ReadConflict`.
- rg/grep share literal/glob/byte-column semantics; non-UTF-8 paths and binary
  content round-trip with padded Base64.
- Planned search cap returns a complete prefix with truncation; an oversized
  first event is `ProtocolError`; a real engine status >1 is fixed/redacted.
- Five hosts concurrently spooled 40 MiB into ten mode-0600 files, completed
  below the serial timing bound, kept measured RSS growth below 32 MiB, and
  removed every internal file afterward.

## Final Verification

- `cargo fmt --check`: passed
- `cargo clippy --all-targets --all-features -- -D warnings`: passed
- `cargo test --test remote_ops -- --nocapture`: 16 passed, 0 failed
- `cargo test --all-targets`: 106 passed, 0 failed
- `git diff --check`: passed
- `__pycache__`: both pre-existing untracked trees preserved and unstaged

Commit: recorded in the controller handoff because the report is included in
the same single commit.
