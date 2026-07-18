# Task 5 Report: Safe Atomic Write and Guarded Delete

Date: 2026-07-18

## Status

- Implementation and review-fix work is present in the Task 5 worktree.
- No review-round commit was created by the Task 5 agent.
- Controller full formatting, lint, and all-target gates are still pending after the latest review fixes.
- Pre-existing untracked `ssh_bridge/__pycache__/` and `tests/__pycache__/` directories were preserved.

## Outcome

Task 5 adds a Rust-only, fixed-script safe-write operation with strict Create and Replace semantics, raw stdin streaming, complete-file SHA-256 verification, mode preservation, bounded closed protocols, one mutation attempt, cleanup ownership, cancellation handling, and `MutationOutcomeUnknown` for ambiguous post-spawn outcomes. It also adds a crate-private guarded delete for Task 6.

Full probes and per-operation sentinels exercise the same security-sensitive GNU command forms. Capability mismatch is emitted only before caller stdin or caller-root mutation and invalidates only a future request. Operational utility failures remain unknown rather than being mislabeled as semantic drift.

## Review findings A-D

### A. Create hard-link directory-follow race

RED command:

```text
cargo test --test remote_ops task5_create_link_race_never_follows_a_symlink_to_an_outside_directory -- --nocapture
```

The current `ln -- source target` followed a target raced to a symlink-to-directory. The outside directory contained two entries instead of one; the outcome was also `MutationOutcomeUnknown` instead of a provable typed conflict.

A companion full-probe RED made a shim discard the future `-T` flag only for a symlink-to-directory destination. `safe_write` incorrectly remained true.

GREEN changes and evidence:

- The shared capability and write helper is exactly `ln -T --`.
- Full probe and write sentinel both attempt linking to a symlink-to-directory and require failure, preserved symlink type, and no nested hard link.
- The upload-race test passes with the outside directory and referent unchanged, the raced symlink preserved, and `WriteConflict` returned with P1/C1.
- `capability_probe_rejects_each_incompatible_exact_behavior` and the write exact-form sentinel matrix pass.

### B. Explicit lstat proof for symlinks

Two REDs established that neither the full probe nor write sentinel explicitly required lstat to report a symlink:

- The new `lstat-symlink-no-follow` write matrix case returned a successful caller write instead of capability mismatch.
- A full-probe stat shim returned a valid regular-file record for the symlink lstat form, but `safe_write` remained true.

Both full probe and write sentinel now call their exact lstat helper on the hostile symlink and require `a???` before the dd/hash/chmod no-follow checks. Both focused tests pass. The post-probe sentinel mismatch occurs before caller-root entries or caller stdin are touched; only the future independent request reprobes and succeeds.

### C. Inaccessible ancestor classification

RED command:

```text
cargo test inaccessible_ancestor -- --nocapture
```

Write and guarded delete both returned `NotFound` for an intended parent below a mode-000 ancestor. Root cause: followed stat and lstat both failed through EACCES, while `[ ! -e ] && [ ! -L ]` was also true and falsely treated that as proof of absence.

The approved minimal classifier runs only after the original followed-parent stat fails. It walks upward using shell parameter expansion, applies exact lstat parsing at each level, and emits:

- `PermissionDenied` only for a visible directory that is not searchable by the effective process;
- `NotDirectory` only for a visible non-directory ancestor beneath an unresolved suffix;
- `NotFound` only after reaching a visible searchable directory beneath an unresolved suffix;
- unknown for unclosed type, identity, race, or symlink-referent evidence.

Both inaccessible-ancestor tests now pass with `PermissionDenied`, targets preserved, permissions restored, and cleanup possible. Direct missing and non-directory parent regressions pass.

A visible parent symlink plus failed followed stat is deliberately `MutationOutcomeUnknown`, nonretryable with `mutation_may_have_applied=true`. Lstat proves only the symlink itself; the follow failure may mean either a dangling referent or a referent hidden by EACCES. Task 5 does not add an unprobed `readlink` resolver or falsely close that ambiguity as `NotFound`.

### D. Required-command preflight

New tests:

- `task5_missing_required_write_command_is_a_future_only_capability_mismatch`
- `task5_missing_required_delete_command_is_a_future_only_capability_mismatch`

The fake SSH fixture can now apply a PATH override to only the first fixed command after a successful full probe. Its minimal PATH contains `sh` so the fixed frame starts, but none of the required mutation utilities.

Both tests were RED as `MutationOutcomeUnknown`. Both are GREEN after adding pre-scratch `command -v` preflights for every external command used by the corresponding sentinel/producer. The first request is exact `RemoteCapabilityMissing` with P1/C1, untouched caller data and empty scratch; the future independent request is P2/C2 and succeeds. Existing nonzero runtime utility tests continue to require unknown outcome rather than capability mismatch.

## Minor hardening

### Exact argument count

`task5_mutation_scripts_reject_extra_arguments_before_sentinel_io` was RED because extra positional arguments were ignored and the script reached the sentinel/domain protocol with exit zero. It is GREEN after adding exact `$# == 7` and `$# == 3` checks immediately after `set -u` and before positional assignments. Extra arguments exit 2 with empty stdout/stderr and no scratch entry.

### Closed stat numeric shapes

The shared full-probe, write, and delete stat parsers now require:

- type: exactly four lowercase hexadecimal characters;
- mode: one through four octal characters, so its textual range is at most `7777`; later semantic checks reject disallowed special bits where relevant;
- UID, size, device, inode, and link count: nonempty decimal digits bounded to at most 20 characters.

The 20-character boundary admits the full unsigned-64 textual width. The shell never performs arithmetic on these fields, avoiding overflow-dependent classification. `task5_shell_stat_parsers_declare_closed_numeric_shapes` passes. A behavioral full-probe shim that supplies consistent 21-digit device/inode values was RED with `safe_write=true` and is GREEN with only `safe_write=false`.

## Earlier Task 5 verification evidence

Before this review round, the post-matrix gate was green:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --test remote_ops -- --nocapture       # 55/55
cargo test --test ssh_transport -- --nocapture    # 60/60
cargo test --all-targets                          # lib 28, core 25, remote 55, ssh 60
git diff --check
```

The five-host write RSS sample reported baseline 48,624 KiB, peak 55,968 KiB, delta 7,344 KiB, below the 65,536 KiB ceiling. Python runtime search was clean, guarded delete remained crate-private, and user pycache directories were untouched.

## Latest focused verification

All new review regressions were run individually from RED to GREEN, including A, B, C, D, exact argc, closed stat shapes, the exact write sentinel matrix, and the exact capability behavior matrix.

The final requested focused aggregate was:

```text
cargo test task5_ -- --nocapture && git diff --check
```

The library phase initially ran 19 tests: 18 passed and the pre-existing runner test `ssh::process::tests::task5_execute_fixed_once_maps_only_spawned_mutations_and_never_retries` failed its final log-count assertion with `left: 1`, `right: 0`. Controller diagnosis showed that the child and asynchronous internal-capture setup start after the same local spawn, so either can win; requiring zero remote log entries contradicted the tested `MutationOutcomeUnknown` contract. The assertion was corrected to permit zero or one invocation while continuing to require one-shot execution, unknown outcome, and complete spool cleanup. The isolated test then passed 10/10 runs. The controller owns the remaining final full-suite gate.

## Files changed in the review round

- `src/capability.rs`
- `src/remote/write.rs`
- `src/ssh/process.rs` (corrected the post-spawn race assertion described above)
- `tests/fixtures/fake-ssh.sh`
- `tests/remote_ops.rs`
- `tests/ssh_transport.rs`
- `.superpowers/sdd/task-5-report.md`

No Python source or pycache content was changed.
