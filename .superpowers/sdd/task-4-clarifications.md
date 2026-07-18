# Task 4 Controller Clarifications

These decisions are binding Task 4 requirements and supplement the Task 4 brief.

## A. Runner integration and allowed scope

1. Task 4 may make the minimum necessary changes to `src/ssh/process.rs`,
   `src/output.rs`, `src/capability.rs`, Cargo dependencies, and the fake SSH
   fixture. `remote` must never spawn SSH or a local shell directly. Add a
   crate-private fixed-protocol execution path owned by `SshRunner`. Its full
   stdout/stderr must be available through forced local spooling and bounded,
   streaming page consumption; do not infer protocol bytes from previews.
2. Fixed operations execute a compile-time POSIX script as
   `exec sh -c <quoted-script> codex-ssh-bridge-op <quoted positional args...>`.
   The runner owns this rendering and uses the one `shell_word` encoder. User
   values never become script text and the operation is not routed through the
   arbitrary user-command renderer. Results report the actual fixed interpreter
   as POSIX sh.
3. Extend the capability protocol and tests to functionally probe every exact
   non-POSIX behavior Task 4 uses (`rg --json`, GNU `find` framing, GNU
   `grep` framing/options, `stat --printf`, and the selected read-slicing
   primitives). Mere `command -v` and a generic Linux assumption are not enough.
4. A fixed read-only operation may invalidate capability state and re-probe at
   most once only after an explicit internal capability-mismatch result. Do not
   retry transport errors, cancellation, protocol corruption, filesystem
   errors, or any future mutating operation automatically.
5. `base64`, `serde_json` as a runtime dependency, and `globset` are authorized
   when the implementation needs them. Do not add a general async/runtime
   dependency when Tokio or existing code suffices.

## B. Public Task 4 shape and provenance

6. `RemoteBridge::new(Arc<SshRunner>)` is the facade. `hosts()` is async but
   purely local and takes no cancellation token. `list`, `stat`, `read`,
   `search`, and `output_read` take a typed request plus a
   `CancellationToken`. `SshRunner` exposes only the minimum crate-private
   config/output/capability views required by the facade.
7. Use the requested fields from the approved tool signatures. Optional/default
   semantics belong in `RemoteBridge`, not in the eventual MCP handler:
   list has host/path/depth/include_hidden/max_entries; stat has host/paths;
   read has host/paths/start_line/max_lines/max_bytes; search has
   host/query/path/globs/max_results plus `binary` defaulting false; output-read
   has output_ref/stream/offset/max_bytes. Validate every field before `ssh -G`.
8. Add optional output provenance to `OutputStore` entries and attach it in
   `SshRunner`: host alias, physical root, and actual shell metadata. Public
   `output_read` accepts only a provenanced reference. Fixed-protocol internal
   spools are consumed and removed internally and are never exposed as tool
   references. Preserve the opaque-token and unknown/expired error behavior.
9. `remote_hosts` never performs I/O. Configured root and read-only mode are
   always present; physical root and shell are cached `Option` values until a
   host has actually been probed.

## C. Defaults and hard ceilings

10. Bind these limits: each UTF-8 input path at most 64 KiB; stat paths at most
    256; read paths at most 32; list depth default 1 and `1..=32`; list entries
    default 1,000 and hard maximum 10,000; search results default 100 and hard
    maximum 10,000; query at most 64 KiB; at most 128 globs and 4 KiB per glob;
    read start line default 1; max lines default 2,000 and hard maximum 100,000.
    Empty path uses `.` only where the signature declares that default; reject
    empty host/query and embedded NUL.
11. Read `max_bytes` is the aggregate raw-byte budget for the whole batch,
    consumed in request order. It defaults to `read_chunk_bytes` and is bounded
    by the host's effective `max_read_bytes` (compiled maximum 1 MiB). Later
    entries remain represented and are marked truncated when the budget is
    exhausted. It is not a per-file 32 MiB amplification path.
12. List/stat/search protocol bytes are bounded by the effective
    `max_frame_bytes` (compiled maximum 8 MiB) and by entry/result ceilings.
    Force-spool and parse pages incrementally so five hosts do not each retain a
    complete 8 MiB frame in Rust heap. Checked arithmetic applies everywhere.

## D. Paths, roots, and symlinks

13. Each path-bearing result uses lossless `actual_path` and `relative_path`.
    `actual_path` means the normalized configured-root absolute operand actually
    passed to SSH; `relative_path` is configured-root-relative. The envelope's
    `physical_root` is informative. Never fabricate a canonical path by joining
    physical root and relative path because intermediate symlinks may differ.
14. The configured root itself may be a symlink. List/stat use lstat/no-follow;
    list/search do not follow directory symlinks. Read follows the final symlink,
    including one that reaches outside the configured root, as the approved
    threat model says roots are an operational guard and not confinement.
15. Inputs remain UTF-8. Remote non-UTF-8 names are lossless
    `EncodedValue { encoding: Utf8 | Base64, value }`, with RFC 4648 standard
    padded Base64 produced locally. Never use replacement characters. Apply the
    same representation to both relative and actual paths.

## E. Read semantics

16. `sha256` is always the 64-character lowercase digest of the complete raw
    file, without a prefix. When the returned bytes are the complete file, hash
    those bytes locally. When selection or byte/line ceilings truncate the
    result, obtain a remote whole-file digest and guard it with hash-before and
    hash-after; differing hashes return a per-file `ReadConflict` and no
    misleading content/version.
17. Content is binary when it contains NUL or is not valid UTF-8. Text is
    `Utf8`; binary is RFC 4648 standard padded `Base64`, encoded locally. Limits
    count raw bytes, not Base64 expansion, while the final wire still obeys the
    global frame ceiling.
18. `start_line` is one-based. `max_lines` applies by LF to arbitrary raw bytes,
    including binary; a final non-LF segment is a line. Return
    `truncated_before`, `truncated_after`, and their OR as `truncated`.
19. Validate the entire batch before launch. Missing, unreadable, and
    wrong-file-kind outcomes are safe per-file error entries and do not prevent
    other files from being read. Transport, cancellation, protocol, and global
    output-limit failures abort the batch.
20. Add stable `ReadConflict`, `NotFound`, `PermissionDenied`, and
    `NotDirectory` error codes with fixed safe messages. Do not reuse
    `WriteConflict` for a read race.
21. Implement a batched API using one fixed SSH operation per file (choice A),
    scheduled with bounded concurrency and returned in request order. This is
    the safe raw-binary framing boundary and must still share the runner's
    global/per-host limits. Do not use remote temp files or remote Base64 for
    reads. stdout is raw selected bytes; stderr is strict bounded metadata.

## F. List and stat semantics

22. List depth 1 means direct children and excludes the requested directory.
    `include_hidden=false` prunes an entry when any traversed relative component
    starts with `.`. Sort by raw relative-path bytes. `max_entries` counts only
    returned entries and fetch enough information to set `truncated=true` iff at
    least one more qualifying entry exists.
23. Exact kinds are file, directory, symlink, block device, character device,
    FIFO, socket, and other. Metadata is size `u64`, mode low 12 bits `u32`,
    mtime seconds `i64`, and mtime nanoseconds `u32`. Do not add uid, gid,
    inode, or symlink target in Task 4.
24. Stat missing/unreadable values are per-entry errors. A missing list root or
    non-directory list root is an operation error. List does not hash files.

## G. Search semantics

25. Query is a literal byte/string search, not a regex: use rg fixed-strings and
    grep `-F`. A future regex mode must be explicit; do not expose differing
    regex dialects under this API.
26. Search includes hidden and ignored files, does not follow symlinks, and uses
    identical semantics for both engines.
27. Globs are positive, configured-root-relative, slash-aware `globset`
    patterns. Support `*`, `?`, character classes, and `**`; reject leading
    `!`, absolute/traversal/NUL patterns. For semantic identity, enumerate a
    bounded candidate set, apply the same local matcher, then invoke rg or grep
    on explicit candidates in bounded batches. A 10,000-candidate or 8 MiB
    enumeration ceiling sets `truncated=true`; never silently claim a complete
    search after hitting it.
28. Add `binary: bool = false`. With false both engines ignore binary files.
    With true, a functionally probed rg may search them; decode rg's byte form
    and re-encode the public value locally. The grep fallback returns
    `RemoteCapabilityMissing` before content search when binary=true.
29. `rg --json` is strict, bounded newline-framed JSON; this is the approved
    exception to NUL framing "where supported". Fallback filename framing is
    NUL-based. Reject a single oversized event and malformed/unknown required
    fields as `ProtocolError`.
30. `SearchMatch` has lossless actual/relative path, one-based line, one-based
    byte column, and encoded content. Do not expose submatch arrays in Task 4.
    The envelope includes engine `rg|grep`, truncation, and actual shell. rg
    exit 1 is a successful empty result.

## H. Labels, output paging, and error grouping

31. To avoid wire amplification, `remote=true`, host, physical root, and shell
    appear once in each operation envelope, not in every nested entry. This
    intentionally refines the brief's ambiguous "every entry": every returned
    tool result is unmistakably remote, while 10,000 matches do not repeat a
    long root. Each `HostInfo` is its own host result and therefore carries
    `remote=true`.
32. Every operation that actually contacts a host reports actual POSIX-sh shell
    metadata. Hosts reports cached optional capability metadata. Output-read
    uses the reference provenance. Do not repeat metadata per nested entry.
33. Caller shape/range errors are `InvalidArgument` or `RequestTooLarge`;
    lexical traversal is `PathOutsideRoot` before launch; capability mismatch is
    `RemoteCapabilityMissing`; malformed/overflow framing is `ProtocolError`
    with no partial result; expected remote filesystem failures use the stable
    per-entry codes above; SSH/cancel/timeout keep runner codes. Error text is
    fixed and never copies arbitrary remote stderr/path content.
34. All count/length/offset calculations are checked. Parsers read at most one
    bounded extra record/byte to prove truncation and do not retain it. User
    values are positional data only. `output_read` page offsets count raw bytes;
    return page data as UTF-8 only when the page is valid UTF-8 and contains no
    NUL, otherwise local padded Base64, with an explicit encoding field.

## I. Design-review corrections

35. Search is line-oriented. Reject CR or LF in `query` during local validation
    so rg and grep fixed-string semantics and the one-line match result remain
    identical. This is in addition to empty/NUL/size rejection.
36. Bound total encoded request data by `max_frame_bytes` before launch. In
    particular, stat must not put up to 256 x 64-KiB paths in one command line.
    Send normalized stat operands as NUL-delimited stdin and reconstruct them
    with the functionally probed NUL path, or use bounded fixed invocations;
    preserve request order and whole-batch prevalidation. Never depend on the
    host's `ARG_MAX`.
37. The Task 4 design must freeze the exact fields and serde representation for
    every public result and nested success/error entry before RED. Per-entry
    errors use a closed serializable shape with stable code, fixed message, and
    no untrusted text; do not expose Rust's implementation-dependent `Result`
    serialization.
38. `CAPABILITY_MISMATCH` is a strict internal protocol record emitted with
    remote exit status zero so the fixed runner does not erase it as
    `RemoteExit`. It must name only a compile-time capability key already
    required by that operation; unknown/extra/malformed mismatch data is
    `ProtocolError`, not a retry trigger.
39. The search design must state an implementable global result-lookahead and
    byte-bound mechanism that uses only functionally probed behavior, preserves
    the actual rg/grep exit status, and works in POSIX sh without `pipefail`.
    It may use bounded candidate batches or a securely created/trapped remote
    scratch file for search only. It may not claim exact truncation by parsing
    an unbounded completed spool, and it may not convert OutputLimit into a
    successful partial result after OutputStore has discarded incomplete data.
40. Every fixed internal spool is guarded by a cleanup owner at facade entry so
    Rust future cancellation/abort as well as handled returns eventually remove
    it; TTL is fallback, not the ordinary cleanup mechanism.

## J. Formal-review corrections

41. The seven Task 4 functional flags are behavioral contracts for the exact
    production command forms, not availability hints. Probe binary NUL,
    no-follow/root-follow, depth, pre-epoch nanoseconds, exit statuses, the
    parent-held same-FIFO-fd drain, and cleanup. PATH-prepended incompatible
    shims must make the affected flag false independently. In `local-fixed`
    mode the fake SSH fixture executes the real capability script by default
    and must not synthesize success.
42. The general `SshRunner` fixed executor performs one attempt. Strict
    exit-zero `CAPABILITY_MISMATCH` interpretation, invalidation, reprobe, and
    the sole optional second attempt belong to an explicit crate-private
    `RemoteBridge` read-only wrapper. Each real read-only script may emit that
    marker only after a preflight for one of its own static required keys
    genuinely fails. Task 5 writes must not inherit retry. Transport,
    filesystem, ordinary remote-exit, cancellation, output-limit, and protocol
    errors never retry.
43. `src/remote/protocol.rs` uses a real 64-KiB `SpoolCursor` over
    `InternalCapturedOutput`. NUL fields/groups and JSON lines may cross page
    boundaries. List/stat/search never aggregate an entire frame in one `Vec`;
    they retain only an incomplete bounded record plus the result ceiling and
    one lookahead. Five concurrent hosts must successfully parse 40 MiB of
    spooled protocol data with measured RSS growth below 32 MiB.
44. List sends `show_hidden` and `max_entries` to the fixed script. Remote find
    prunes any hidden root-relative component before descent, and a remote
    qualifying counter emits no more than `max_entries + 1` records. Hidden
    entries neither consume the count nor create truncation. The Rust parser
    retains at most the same lookahead.
45. Search glob validation and matching share the same constructor:
    `GlobBuilder::literal_separator(true)`. Root-relative `*`, `?`, character
    classes, and `**` have identical validation and raw-path matching semantics.
46. Every list/search bounded helper keeps one parent FIFO read fd open, copies
    `limit + 1` bytes to bounded scratch, drains the remainder from that same fd
    to `/dev/null`, waits for the real producer/engine/xargs statuses, and makes
    any nonzero real status win over the cap. Planned SIGPIPE is not a success
    mechanism. Search rejects unknown rg event kinds, retains at most
    `max_results + 1` matches and 10,001 candidates, and returns an error for a
    complete capped prefix followed by a real exit greater than one.
47. Read follows the final symlink. A dangling final symlink is `NotFound`; an
    existing target that is deterministically unreadable is
    `PermissionDenied`. If parent-directory search permission makes existence
    itself indeterminate, return a fixed safe filesystem error and never copy
    stderr or the path. Keep the existing 64-KiB quote and checked rendered
    command plus stdin bounds unchanged.

## K. Second formal-review corrections

48. Capability flags compare complete production-shaped behavior, not selected
    substrings. `find_nul` proves root-follow, descendant no-follow, depth,
    hidden pruning, newline names, and exact `%P/%y/%s/%m/%T@` raw records.
    `rg_json` proves text and byte JSON, binary false/true, match fields, and
    statuses 0/1/>1. `search_bound` proves private mode-0700 scratch, `mkfifo`,
    a parent-held same fd for head plus drain, sequential xargs and child
    failure propagation, full-prefix later-error priority, traps, and cleanup.
    Fine-grained PATH shims retain ordinary command availability and make only
    the targeted functional flag false.
49. Every real read-only script runs a cheap exact sentinel for each required
    production form it is about to use. A genuine sentinel mismatch may emit
    only that request's static required key and trigger exactly one
    invalidation/reprobe/retry; a second mismatch is
    `RemoteCapabilityMissing`. Ambiguous filesystem, transport, parser, and
    engine failures never become mismatch markers. Sentinels add no SSH round
    trip, keep scratch private/trapped, and their warm local-fixed integration
    latency is recorded as non-threshold evidence. A utility that returns
    nonzero while creating sentinel scratch is an ordinary setup failure; a
    successful invocation whose resulting mode/type/output violates the exact
    production contract is a capability mismatch.
50. Raw configured-root joining inserts `/` only when the base is nonempty and
    does not already end in `/`. A host configured with root `/` therefore
    reports `/etc`, never `//etc`, and search derives `tmp/x` from `/tmp/x`.
    Search reserves the exact runner-rendered fixed command bytes before adding
    NUL stdin candidates; if the command alone leaves no room for one candidate
    it returns `RequestTooLarge`. The total command-plus-stdin frame limit
    remains unchanged.
