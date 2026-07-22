# Performance Evidence

## Measurement host

- Host: Raspberry Pi-class aarch64 Linux machine
- Kernel: Linux aarch64 (exact kernel release intentionally omitted)
- Rust: `rustc 1.91.1 (ed61e7d7 2025-11-07)`, LLVM 21.1.2
- OpenSSH: 10.0p2 Debian 7+deb13u4, OpenSSL 3.5.6
- Profile: Cargo `release`, thin LTO, one codegen unit, stripped symbols

These are acceptance measurements for the framed persistent-session transport,
not universal throughput claims. Network latency, SSH server load, cipher choice,
filesystem behavior, and CPU architecture dominate real-server results.

## Reproduce

```bash
cargo test --release --test mcp_tools task78_release_dispatch_ -- --nocapture
cargo test --test session -- --nocapture
cargo test --release --test mcp_tools task8_five_hosts_ -- --nocapture
cargo test --release --test mcp_tools task8_cancel_process_ -- --nocapture
cargo test --release --test mcp_tools task8_output_rss_ -- --nocapture
cargo test --release --test mcp_protocol task7_wide_json_rss_ -- --nocapture
cargo test --release --test performance_acceptance -- --nocapture
CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1 cargo test --release --test real_ssh -- --nocapture
```

Latency tests warm the relevant path, collect at least 120 samples, sort raw durations, and enforce the compiled p95 thresholds. RSS tests run fresh child processes and report warmed baseline, observed peak, and delta from `/proc/self/status`.

## Recorded values

| Case | Samples / shape | Observed | Gate |
|---|---:|---:|---:|
| Bridge-only MCP dispatch | 200 | p50 5.185 µs, p95 7.037 µs, max 93.573 µs | p95 < 2 ms |
| Complete fake-SSH MCP call | 120 | p50 ~88 ms, p95 ~132 ms, max ~153 ms | p95 < 250 ms |
| Five hosts, one-second command each | 5 concurrent | 1.027630313 s wall time; resolve/probe/command calls each exactly 5, with no root-observe calls | < 1.5 s |
| Cancellation to whole process-group exit | one TERM-ignoring fixture | 51.621590 ms | < 250 ms |
| Bounded persistent-session output plus retained models | fresh child | 8 MiB request, bounded resident capture | < 32 MiB |
| Maximum-budget wide JSON array | fresh child | RSS delta 8,528 KiB | < 48 MiB |
| Maximum-budget wide JSON object | separate fresh child | RSS delta 17,216 KiB | < 48 MiB |
| Maximum MCP payload | complete framed case | payload 8,388,608 bytes; newline-delimited frame 8,388,609 bytes | exact compiled ceiling |
| Tool-list / required output page | complete MCP serialization | 6,947 / 1,048,576 bytes | within wire budget |

The complete fake-SSH p95 includes the bounded remote command process and output capture. The first request for an alias pays local identity resolution, capability probing, and SSH session startup; warm commands reuse one persistent dispatcher session and send one request frame, so they do not pay another SSH handshake, `ssh -G`, or root observation. Capability root metadata is connection-time diagnostic context, not a warm authorization round trip. The five-host test demonstrates absence of cross-host head-of-line blocking at the stated concurrency, not capacity beyond configured limits.

## Why memory stays bounded

- Input framing rejects the first byte past the configured limit and then recovers at the next newline.
- Strict JSON applies aggregate depth, node, object-member, and key-byte budgets during parsing.
- Commands stream stdin and drain stdout/stderr concurrently.
- Large output spills to private files under shared byte, entry, and serialization-job quotas.
- MCP rendering retains oversized details once and returns a compact provenance-bound reference.
- Paging opens independent cursors rather than cloning a shared resident output buffer.
- Array and object RSS gates run in different fresh children so allocator retention cannot hide amplification.

## Rust, Bash, and SSHFS

The native Rust bridge removes interpreter startup from every MCP frame and keeps validation, scheduling, cancellation, quotas, and serialization in one process. A persistent SSH dispatcher removes repeated remote shell setup for warm operations. Replacing the bridge with Bash would move JSON correctness, frame bounds, and concurrent process ownership into shell text without improving the dominant SSH/network latency.

The bridge still uses the remote Bash or POSIX sh selected by capability probing because commands must execute where the server's tools and data live. Omitted `remote_run.shell` means Bash; `sh` is an explicit retry choice after a Bash capability error. There is no hidden fallback.

The persistent session adds a fixed startup cost once per alias, then multiplexes independent request frames. A long command does not block another request until the configured per-host capacity is exhausted; a session transport failure invalidates all pending requests and is not automatically retried.

SSHFS is optional because repository walks and builds can turn many small filesystem calls into network round trips. The structured tools batch list/stat/read/search work remotely and return bounded results, which reduces both latency and Agent-side context pressure.

The persistent-session gates should be rerun on the target host; the following
localhost fixture records real-SSH behavior separately from fake-transport timing.

## Isolated real OpenSSH

`tests/real_ssh.rs` generated temporary Ed25519 host, client, and wrong-host keys; launched an unprivileged OpenSSH 10.0p2 `sshd` on a localhost high port; and completed in 2.80 seconds with one pass, zero failures, and no skip. It verified strict known-host rejection, public-key login, ControlMaster inode reuse, connection-time root diagnostics, trusted account-login-shell resolution, explicit Bash, explicit sh, strict shell selection, hostile quoting, list/stat/read/fixed-string search, guarded write/patch, timeout, cancellation uncertainty, and cleanup of the master sockets, remote test processes, and daemon.

The managed sandbox denies local `bind(2)`, so the final fixture was run with approved local-network execution. Developer runs without `CODEX_SSH_BRIDGE_REQUIRE_REAL_SSH=1` retain one visible skip reason when facilities are unavailable. Release acceptance uses the required-mode command above: setup failure is fatal, so a required run cannot report a skip as a pass. The recorded real-SSH run completed without a skip.

The real-SSH wording above predates the persistent dispatcher path; current MCP accepts `bash`, `sh`, and `login`, with omitted shell meaning `bash`. There is no silent Bash-to-sh fallback.
