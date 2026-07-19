# Performance Evidence

## Measurement host

- Host: Raspberry Pi-class aarch64 local machine (`aarch64-test-host`)
- Kernel: Linux `6.18.34+rpt-rpi-2712` aarch64
- Rust: `rustc 1.91.1 (ed61e7d7 2025-11-07)`, LLVM 21.1.2
- OpenSSH: 10.0p2 Debian 7+deb13u4, OpenSSL 3.5.6
- Profile: Cargo `release`, thin LTO, one codegen unit, stripped symbols

These are acceptance measurements, not universal throughput claims. Network latency, SSH server load, cipher choice, filesystem behavior, and CPU architecture dominate real-server results.

## Reproduce

```bash
cargo test --release --test mcp_tools task78_release_dispatch_ -- --nocapture
cargo test --release --test mcp_tools task78_release_fake_call_ -- --nocapture
cargo test --release --test mcp_tools task8_five_hosts_ -- --nocapture
cargo test --release --test mcp_tools task8_cancel_process_ -- --nocapture
cargo test --release --test mcp_tools task8_output_rss_ -- --nocapture
cargo test --release --test mcp_protocol task7_wide_json_rss_ -- --nocapture
cargo test --release --test performance_acceptance -- --nocapture
cargo test --release --test real_ssh -- --nocapture
```

Latency tests warm the relevant path, collect at least 120 samples, sort raw durations, and enforce the compiled p95 thresholds. RSS tests run fresh child processes and report warmed baseline, observed peak, and delta from `/proc/self/status`.

## Recorded values

| Case | Samples / shape | Observed | Gate |
|---|---:|---:|---:|
| Bridge-only MCP dispatch | 200 | p50 4.755 µs, p95 6.550 µs, max 107.089 µs | p95 < 2 ms |
| Complete fake-SSH MCP call | 120 | p50 1.480011 ms, p95 3.560485 ms, max 11.365453 ms | p95 < 10 ms |
| Five hosts, one-second command each | 5 concurrent | 1.020463499 s wall time; prepare/run/capability calls each exactly 5 | < 1.5 s |
| Cancellation to whole process-group exit | one TERM-ignoring fixture | 51.381166 ms | < 250 ms |
| 64 MiB output plus retained models | fresh child | baseline 3,888 KiB, peak 6,128 KiB, delta 2,240 KiB | < 16 MiB |
| Maximum-budget wide JSON array | fresh child | RSS delta 8,528 KiB | < 48 MiB |
| Maximum-budget wide JSON object | separate fresh child | RSS delta 17,216 KiB | < 48 MiB |
| Maximum MCP payload | complete framed case | payload 8,388,608 bytes; newline-delimited frame 8,388,609 bytes | exact compiled ceiling |
| Tool-list / required output page | complete MCP serialization | 6,947 / 1,048,576 bytes | within wire budget |

The fake-SSH p95 includes process creation and the complete bridge/MCP rendering path but not a network round trip. The five-host result demonstrates absence of cross-host head-of-line blocking at the stated concurrency, not capacity beyond the configured limits.

## Why memory stays bounded

- Input framing rejects the first byte past the configured limit and then recovers at the next newline.
- Strict JSON applies aggregate depth, node, object-member, and key-byte budgets during parsing.
- Commands stream stdin and drain stdout/stderr concurrently.
- Large output spills to private files under shared byte, entry, and serialization-job quotas.
- MCP rendering retains oversized details once and returns a compact provenance-bound reference.
- Paging opens independent cursors rather than cloning a shared resident output buffer.
- Array and object RSS gates run in different fresh children so allocator retention cannot hide amplification.

## Rust, Bash, and SSHFS

The native Rust bridge removes interpreter startup from every MCP frame and keeps validation, scheduling, cancellation, quotas, and serialization in one process. Replacing it with Bash would move JSON correctness and concurrent process ownership into shell text without improving the dominant SSH/network latency.

The bridge still uses the remote Bash or POSIX sh selected by capability probing because commands must execute where the server's tools and data live. Selection and fallback are metadata, not hidden control flow.

SSHFS is optional because repository walks and builds can turn many small filesystem calls into network round trips. The structured tools batch list/stat/read/search work remotely and return bounded results, which reduces both latency and Agent-side context pressure.

The final `tests/performance_acceptance.rs` run repeated every gate above in release mode. The following localhost fixture records real-SSH behavior separately from fake-transport timing.

## Isolated real OpenSSH

`tests/real_ssh.rs` generated temporary Ed25519 host, client, and wrong-host keys; launched an unprivileged OpenSSH 10.0p2 `sshd` on a localhost high port; and completed in 1.85 seconds with one pass, zero failures, and no skip. It verified strict known-host rejection, public-key login, ControlMaster inode reuse, explicit Bash, explicit sh, visible auto-to-sh fallback, hostile quoting, list/stat/read/fixed-string search, guarded write/patch, timeout, cancellation uncertainty, and identity-checked cleanup of the master sockets, remote test processes, and daemon.

The managed sandbox denies local `bind(2)`, so the final fixture was run with approved local-network execution. If a host genuinely lacks the required local facilities, the test prints one explicit skip reason; this recorded run did not skip.
