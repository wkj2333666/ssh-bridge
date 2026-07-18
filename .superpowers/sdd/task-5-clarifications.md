# Task 5 Controller Clarifications

These decisions are binding Task 5 requirements.

1. `RemoteBridge::write(request, CancellationToken)` is public. `WriteRequest`
   has host, path, content string, `WriteEncoding::{Utf8, Base64}`, and
   `WriteMode::{Create, Replace { expected_sha256: Option<String> }}`. Task 5
   adds no public delete method.
2. UTF-8 content is its exact bytes and may be empty or contain NUL. Base64 is
   RFC 4648 standard padded canonical data. Use base64 0.22's explicitly strict
   standard engine (`RequireCanonical` padding with trailing bits disallowed),
   which is equivalent to decode-then-re-encode equality without allocating a
   second encoded string. Empty Base64 is the valid encoding of empty bytes.
   Reject whitespace, URL-safe alphabet, missing padding, and noncanonical
   trailing bits. Limits and hashes use decoded bytes.
3. Resolve host/read-only/path, decode content, validate size/hash, and perform
   checked rendered-command-plus-stdin bounds before `ssh -G`. Decoded content
   must be no larger than the effective `max_write_bytes`; the fixed invocation
   must fit `max_frame_bytes`. Empty content is valid. Reject an empty target,
   `.`, a target resolving to the configured root, NUL, paths over 64 KiB, and
   any lexical escape before launch.
4. Staging remains mode 0600. Create installs mode 0600. Replace preserves the
   prior target's ordinary low 0777 permission bits, but rejects a target with
   setuid, setgid, or sticky bits as `WriteConflict`. Keep the temporary file
   0600 through the atomic rename, then chmod the installed target and verify
   the final mode. A failure after rename but before verified chmod is an
   unknown mutation outcome, never a false success. This avoids exposing a
   group/other-writable temporary pathname. Add the exact functional chmod
   behavior to the write capability.
5. Do not create parents. Missing parent is `NotFound`, non-directory parent is
   `NotDirectory`, and a deterministically inaccessible parent is
   `PermissionDenied`. Configured-root and intermediate parent symlinks remain
   allowed by the operational-guard threat model. The script enters the parent
   and thereafter uses only `./<basename>`. It never follows the final target
   symlink.
6. Create succeeds only when no directory entry exists. File, directory, live
   symlink, and dangling symlink are all `WriteConflict`. A target appearing
   during upload is caught by same-directory hard-link no-clobber and is also
   `WriteConflict`. Create never overwrites and never makes directories.
7. Replace requires an existing, lstat-regular, non-symlink target at final
   commit. Missing is `NotFound`; directory, special file, live symlink, and
   dangling symlink are `WriteConflict`. `expected_sha256=None` is intentional
   last-writer-wins subject to the same final type/mode guard. `Some` may be
   checked early but must be recomputed immediately before rename. A type,
   identity, expected-hash, or special-mode race is `WriteConflict` when the
   script can prove it before commit.
8. An expected hash is valid only for Replace and must be exactly 64 lowercase
   hexadecimal characters without a prefix. Invalid values fail locally with
   zero launch. Rust hashes decoded content and passes lowercase hash plus raw
   byte length. The remote side must independently verify staging size/hash
   before installation and again after every staging metadata change that could
   affect safety.
9. Require `umask 077`, same-directory `mktemp`, no-follow `dd`, regular and
   non-symlink staging type, effective-UID ownership, initial mode 0600, exact
   size/hash, same device as parent, and link count one. Target ownership is not
   restricted; remote-account and directory permissions remain the hard
   boundary. Successful typed results require the temporary pathname to be
   absent. Never expose it.
10. Add production-shaped functional capabilities `safe_write` and
    `guarded_delete`, tested only inside the probe's private tree. They cover the
    exact mktemp/dd/stat/id/hash/chmod/ln/mv/rm/type/mode/no-clobber/cleanup
    forms used. Each mutation script runs a cheap exact sentinel before reading
    caller stdin or touching the caller target. Cached false fails immediately.
    A genuine pre-mutation sentinel mismatch returns
    `RemoteCapabilityMissing`, invalidates the cache for a future independent
    request, and does not retry the current request. Setup/I/O failures are not
    capability mismatches. No mutation path calls the Task 4 read-only retry
    wrapper.
11. One write API call has at most one fixed mutation child. All target
    prechecks, staging, raw stdin transfer, final recheck, install, permission
    finalization, verification, and cleanup occur in that one static script.
    Initial uncached `ssh -G` and capability probe happen after local validation
    and do not count as a mutation attempt. There is no retry after capability,
    transport, timeout, cancellation, protocol, status-255, or disconnect
    failure.
12. Add a crate-private `guarded_delete` for Task 6. Its request requires host,
    normalized non-root path, and a mandatory valid expected SHA-256. It rejects
    read-only hosts locally and uses one fixed child. Only an existing
    lstat-regular non-symlink whose hash still matches immediately before `rm`
    may be removed. Missing is `NotFound`, and hash/type/symlink/race is
    `WriteConflict`. Missing is not idempotent success. After unlink, confirm
    the directory entry is absent. It has no public serde/MCP surface.
13. `WriteResult` has a flattened `RemoteContext`, lossless actual/relative
    path, `WriteOperation::{Create, Replace}`, `raw_bytes: u64`, complete-file
    lowercase `sha256`, final `mode: u32`, and
    `temporary_cleanup_confirmed: bool`. The boolean is explicit cleanup
    evidence and can only be true in a successful result. The internal delete
    result has paths, deleted hash, and `absence_confirmed`; neither result ever
    contains a temporary path or remote stderr.
14. Expected domain outcomes use remote exit zero and one closed NUL protocol
    on stdout; stderr must be empty. Allowed records are success,
    `WriteConflict`, `NotFound`, `NotDirectory`, `PermissionDenied`, and
    `CapabilityMismatch { capability: safe_write | guarded_delete }` with an
    exact field set. CapabilityMismatch is valid only when the script proves it
    has not read caller stdin or touched the caller target; it invalidates only
    a future request and never retries the current mutation. Unknown,
    duplicate, extra, malformed, or trailing data is `ProtocolError`.
    Read-only is `ReadOnlyHost`; local input errors use the existing
    argument/size/path codes; capability failure is
    `RemoteCapabilityMissing`. A wrong final target type is `WriteConflict`.
15. Add stable `MutationOutcomeUnknown` serialized as
    `MUTATION_OUTCOME_UNKNOWN` and
    `ErrorDetails.mutation_may_have_applied: Option<bool>`. Any ambiguous error
    after a mutation child may have started, including malformed success
    protocol after exit zero, maps to a fixed non-retryable unknown-outcome
    error with the flag true. Queue/resolve/probe failures before the child keep
    their original error and flag absent/false. Never return `WriteResult`,
    changed status, or cleanup confirmation for an ambiguous outcome.
16. Use the stricter equivalent trap, not a blindly copied one-liner: the EXIT
    trap owns cleanup; HUP/INT/TERM run cleanup and terminate nonzero. The temp
    variable starts empty and cleanup operates only on the controlled mktemp
    pathname. Signal, normal-error, typed-error, and success paths must all have
    explicit cleanup tests.
17. A Replace verifies the installed staged inode's complete size and SHA-256
    while it is still mode 0600. After applying the preserved ordinary mode,
    it verifies the same device/inode, regular non-symlink type, effective-UID
    ownership, exact final mode, size, link count, and absent temporary name,
    but does not reopen the file for hashing. This is required for valid final
    modes such as 0000 and 0200; chmod does not change file content.
18. Parent identity uses a shared, exact, production-probed follow form based
    on GNU `stat -L`. After a successful POSIX `cd "$parent"`, the script must
    compare `stat .` device/inode with the pre-entry followed directory before
    reading stdin or creating staging. A mismatch emits no typed result.
19. Full probe, per-operation sentinel, and caller-data producer must exercise
    the same security-sensitive command forms. Stateful tests cover write and
    delete stat-follow/lstat, dd input/output, hash, link, rename, chmod, and
    remove drift after a successful full probe. A current mutation never
    retries; only a future independent request may reprobe.
20. Content bytes are moved into the runner exactly once and are not cloned.
    After decoding, release the source string as early as ownership permits.
    Add a five-host concurrent 4 MiB test with a measured, deliberately roomy
    RSS-delta ceiling, exactly one mutation child and staging path per host,
    and complete cleanup. Document the unavoidable transient Base64 source
    plus decoded allocation separately from the steady decoded-buffer bound.
21. Any shell helper that changes IFS must restore it on every return path;
    prefer a subshell or one cleanup exit. A malformed hash capture must not
    contaminate the next helper call.
22. `MODE` in the closed mutation protocol is decimal. The script validates
    GNU stat `%a` as octal and converts it explicitly: 0600 is 384 and 0640 is
    416 in the protocol.
23. Exact rendered-frame zero-launch tests include quote-heavy paths so
    `shell_word` expansion, not only raw path length, is counted.
24. Shell variables never contain NUL. Numeric stat records are validated as
    a complete closed ASCII character set before field splitting or pathname
    expansion, and glob expansion is disabled or otherwise made impossible.
25. A fixed mutation may deliberately emit an allowed exit-zero domain or
    capability-mismatch record before reading caller stdin. The local stdin
    writer therefore treats only EPIPE/BrokenPipe for a fixed mutation as an
    early-close condition and continues waiting/capturing; the strict closed
    protocol is the sole adjudicator. Any nonzero exit, malformed record, or
    other stdin I/O failure remains `MutationOutcomeUnknown`. Arbitrary
    `remote_run` stdin behavior is unchanged, and no script drains large input
    merely to avoid EPIPE.
26. Before Base64 decoding allocates its output, checked encoded-length and
    padding arithmetic rejects any input that cannot decode within the host's
    effective write limit. The strict decoder and actual decoded length remain
    authoritative. UTF-8 checks its byte length before `String::into_bytes()`.
27. A sentinel emits capability mismatch only for a proven semantic drift,
    such as a utility reporting success while violating a checked no-follow,
    no-clobber, metadata, cleanup, or exact-result invariant, or a definitely
    missing required command. An otherwise unexplained utility failure or
    scratch I/O/setup failure emits no closed mismatch record and is unknown;
    a silent nonzero exit is not by itself proof of capability drift.
28. Parent classification is evidence-based. A provably missing ordinary path
    component is `NotFound`, but a parent that is itself a dangling symlink is
    `MutationOutcomeUnknown`: after the mutation child has spawned, failure to
    follow that symlink cannot safely distinguish a missing referent from an
    inaccessible or raced referent. The bridge must not retry that request.

Implementation approach A is binding: production-shaped write/delete
capabilities, cheap pre-mutation sentinels, one-shot static scripts, and strict
closed results. Task 4's generic fixed runner remains single-attempt; mutation
never uses read-only retry.
