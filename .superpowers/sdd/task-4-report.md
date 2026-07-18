# Task 4 High-Level Remote Read Report

Date: 2026-07-18

## Formal Review Rework

The first Task 4 implementation commit (`6356179`) was **Not Approved**. The
approved facade/streaming revision corrected all seven Important findings
without weakening their acceptance criteria:

1. exact behavioral capability probes and real `local-fixed` probing;
2. genuine mismatch markers with retry only in the read-only facade;
3. a 64-KiB paged `SpoolCursor` and successful five-host RSS evidence;
4. remote list hidden pruning and qualifying max-plus-one counting;
5. one slash-aware glob builder for validation and matching;
6. same-FIFO-fd drain with final error precedence and bounded strict search;
7. final-symlink `NotFound`/`PermissionDenied` read semantics.

The design, plan, and binding clarification list record these superseding
requirements. The tests below captured RED before each implementation change
and GREEN afterward.

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
- The first implementation's search-cap debugging used planned SIGPIPE. Formal
  review superseded that design: the rework keeps one parent read fd, drains,
  waits, and gives every genuine final error priority over the cap.
- Five-host peak test initially expected `ProtocolError`; it demonstrated the
  stronger correct behavior, `OutputLimit` with no partial result. Its corrected
  assertion passed twice consecutively.
- Exact-probe RED: each PATH shim was still reported compatible because the
  synthetic fixture or an availability-only probe masked the incompatible
  production command form. GREEN independently makes only the shimmed one of
  all seven flags false, executes the real script in `local-fixed`, and leaves
  the private scratch empty.
- Facade-retry RED: retry lived in `SshRunner`, and a fixture-only marker could
  not prove that a real fixed script detected staleness. GREEN uses a stateful
  real `find` shim and observes exactly two probes and two list commands. The
  runner performs one attempt; transport, filesystem, and unknown-marker tests
  prove zero retry.
- Streaming RED: the protocol parser collected a whole frame. GREEN exercises
  NUL fields and JSON lines across 64-KiB pages, plus five successful concurrent
  8-MiB candidate streams (40 MiB total) with RSS growth below 32 MiB.
- List RED: more than a frame of hidden entries consumed the local byte cap and
  incorrectly reported truncation before the visible entries. GREEN prunes
  remotely and counts only qualifying records, returning all visible entries
  with `truncated=false`.
- Glob RED: `*.txt` crossed `/` and selected nested files. GREEN constructs
  validation and both rg/grep matching with the same
  `GlobBuilder::literal_separator(true)` semantics for `*`, `?`, classes, and
  `**`.
- Search-bound RED: a grep shim emitted a complete capped prefix and then exited
  2, but the prefix was returned as partial success; rg also ignored an unknown
  event kind. GREEN drains the same FIFO descriptor, waits for all real final
  statuses before emitting data, returns the redacted engine error, and rejects
  the unknown event as `ProtocolError`.
- Final-symlink RED: a dangling final link did not map to `NotFound`. GREEN
  follows the final link for existence/readability/type decisions, maps a
  dangling target to `NotFound`, and maps a deterministically unreadable target
  to `PermissionDenied` without exposing stderr or path bytes.

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
- Search and bounded list use mode-0700 `mktemp` scratch, trapped FIFO cleanup,
  one parent-held FIFO read descriptor, foreground `head -c remaining+1`, a
  same-descriptor drain, separate producer/engine/xargs status files,
  suppressed utility diagnostics, and no `pipefail`. Every genuine final error
  wins over a bounded prefix.
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
- A search cap returns a complete prefix with truncation only after every real
  final status succeeds; an oversized first event is `ProtocolError`; a real
  engine status >1 is fixed/redacted.
- Five hosts concurrently spooled 40 MiB into ten mode-0600 files, completed
  below the serial timing bound, kept measured RSS growth below 32 MiB, and
  removed every internal file afterward.

## Final Verification

- `cargo fmt --check`: passed
- `cargo clippy --all-targets --all-features -- -D warnings`: passed
- `cargo test --test remote_ops -- --nocapture`: 23 passed, 0 failed
- `cargo test --all-targets`: 117 passed, 0 failed
- `git diff --check`: passed
- `__pycache__`: both pre-existing untracked trees preserved and unstaged

Commit: recorded in the controller handoff because the report is included in
the same single commit.
