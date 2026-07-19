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

## Second Formal Review Rework

The second Task 4 review of commit `710734c` was **Not Approved** with three
Important findings. The R2 rework tightened the exact probe oracles, added
production-form stale sentinels to every read-only operation, and corrected
configured root `/` path joining.

### R2 RED/GREEN evidence

- Exact probe RED: a fine-grained `find` shim corrupted one raw metadata detail
  while preserving command availability and the probe still reported
  `find_nul=true`. GREEN compares the full expected raw path plus
  `%P/%y/%s/%m/%T@` records, including root-follow, descendant no-follow,
  depth, hidden pruning, and a newline name. The rg oracle now checks text and
  byte JSON, binary false/true, match fields, and statuses 0/1/>1. The bounded
  oracle now checks private mode-0700 scratch, FIFO creation, the production
  parent-held same-fd head/drain, sequential xargs and child failure, a full
  prefix followed by a final error, traps, and cleanup. Fine-grained PATH shims
  for find, rg, head, xargs, mktemp, and mkfifo make only the target flag false.
- Stale sentinel RED: a stateful production-form shim produced only one probe
  (`P=1`) because the operation did not detect the stale behavior; a permanently
  bad operation form returned success instead of
  `RemoteCapabilityMissing`. GREEN covers ten list/stat/read/candidate/rg/grep
  sentinel cases. Each passes the full probe, fails the first production-form
  sentinel, then succeeds after exactly one invalidation/reprobe/retry; a second
  mismatch returns `RemoteCapabilityMissing`. Filesystem, transport, parser,
  and genuine engine failures remain ordinary non-mismatch errors.
- 4-KiB refactor RED: adding exact sentinels initially made the conservative
  search reserve exceed 4096, so a valid candidate was omitted before the
  engine and the late-error regression returned an empty result. GREEN uses the
  exact runner rendering length. After final setup-error separation the script
  source sizes are list 3,738 bytes, candidate 2,177, rg 3,680, and grep 3,007;
  a representative complete list rendering is 3,994 bytes. Both the hidden-flood list and
  full-prefix-then-exit-2 search regressions pass with
  `max_frame_bytes=4096`; the command-plus-stdin hard bound is unchanged.
- Root slash RED: a real list with configured root `/` returned `//etc`.
  GREEN inserts a separator only when the base does not already end in `/` and
  asserts exact `/etc` plus the absence of any `//` actual path.

The ten stateful stale-sentinel cases completed in 1.348 seconds locally.
After warming the capability cache, five local-fixed samples per operation
reported these integration-level totals (sentinel included, no network RTT):

- list: p50 23.93 ms, range 23.31–24.14 ms;
- stat: p50 16.03 ms, range 15.91–16.30 ms;
- read: p50 17.36 ms, range 17.22–17.55 ms;
- rg search: p50 42.22 ms, range 41.84–47.30 ms;
- grep search: p50 31.37 ms, range 30.69–36.47 ms.

The latency test records evidence without a timing threshold, so host load does
not turn it into a flaky correctness gate. Sentinels execute inside the one
existing fixed command and add no SSH round trip.

### Final focused-review closure

The pre-commit read-only review found no Critical issues and four Important
edge cases. Each received an observed RED and focused GREEN:

- a quote-heavy query under 4 KiB returned an unexecuted empty/truncated search;
  it now returns `RequestTooLarge` when the rendered command alone cannot fit a
  candidate;
- configured root `/` search rejected `/tmp/x` as outside the root; it now
  derives `tmp/x` and preserves the exact actual path;
- an inaccessible parent returned `NotFound`; walking to the nearest existing
  unsearchable directory now returns the safe `PermissionDenied` entry;
- mktemp setup failure retried and ended as `RemoteCapabilityMissing`; setup
  and I/O failures now remain ordinary `RemoteExit` with `P=1/C=1`, while a
  successful wrong 0755 directory or non-FIFO result remains a genuine stale
  `search_bound` mismatch and retries exactly once.

The review's cleanup recommendation also added an incompatible `rm` shim: the
exact `search_bound` flag becomes false and the outer probe still removes its
private directory.

## Third Formal Review Rework

The R3 review left one Important list-specific gap: the sentinel used a fixed
depth-one find without the real hidden-prune branch, and its xargs checks did
not use production's `-n 100`. A stale utility could therefore pass the full
probe and sentinel, fail only the caller-data form, and return `RemoteExit`
without invalidation.

The new `readonly_stale_list_production_forms_retry_exactly_once` table first
observed that RED for caller depth 3: the stateful find shim produced
`RemoteExit` on the first production command with no refresh. Equivalent shims
cover both hidden-prune operands and xargs `-n 100`. The implementation now
defines compact `lf(root, depth, hidden)` and `lx(...)` functions once inside
`LIST_SCRIPT`; the controlled sentinel and caller-data producer invoke only
those shared forms.

GREEN evidence covers all three one-shot semantic corruptions with exactly two
probes/two list commands, a persistent dynamic-depth corruption as
`RemoteCapabilityMissing` after exactly two probes/two commands, and an
ordinary missing list root as `NotFound` with one probe/one command. Existing
stale, persistent, setup-error, hidden-flood, and root-slash regressions remain
green. Compact internal operands keep the list script at 3,763 source bytes and
a representative complete rendering at 4,011 bytes; the real hidden-flood
fixture still executes with `max_frame_bytes=4096`.

A follow-up review proposed repeating depth-`D`/`D+1` fixtures and more than
100 xargs operands inside every warm list sentinel. That recommendation was
rejected after checking the binding responsibility split: clarification 48's
full capability probe owns exhaustive depth, prune, NUL grouping, and child
failure semantics; clarification 49 requires the per-operation sentinel to be
cheap; and clarification 51 requires the sentinel and producer to call the
same full functions with the caller's dynamic options. Rebuilding those large
fixtures per operation would duplicate the cached probe and undermine the
documented warm-path goal. The retained tests instead isolate the three
production-only forms after a successful full probe and prove their exact
one-refresh behavior.

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
- `cargo test --test remote_ops -- --nocapture`: 31 passed, 0 failed
- `cargo test --all-targets`: 125 passed, 0 failed (12 lib, 25 core,
  31 remote operations, 57 SSH transport)
- `git diff --check`: passed
- `__pycache__`: both pre-existing untracked trees preserved and unstaged

Commit: recorded in the controller handoff because the report is included in
the same single commit.
