# Task 3 Second-Review Fixes Design

## Scope

This design records the focused fixes from the second and third Task 3 reviews:
the four second-review findings plus the command-phase status-255 provenance
gate. Existing runner APIs, output paging, process-group semantics, and limits
remain unchanged.

## Timeout rendering and capability

Validated positive millisecond durations are rendered without floating point as
`secs.{millis:03}s`; for example, 123 ms becomes `0.123s`. The resulting command
uses GNU `timeout --signal=TERM --kill-after=1s` and is covered by a real
`/usr/bin/timeout` execution regression. Zero remains a typed request-validation
error, and conversion remains checked.

The remote probe reports timeout support only when a no-side-effect invocation
of all required options and the decimal-seconds duration syntax exits zero. Its
stdout and stderr are redirected to `/dev/null` so the strict NUL protocol is
not polluted. Finding an executable by name is not sufficient.

## Unified stdin lifecycle

The stdin writer becomes a third supervised future alongside child wait and
stdout/stderr capture. Successful completion requires all three futures. This
keeps cancellation, deadline, and output-limit branches active when an SSH
parent exits but a descendant retains stdin. Forced termination sends TERM,
waits 50 ms, sends KILL, and gives an unfinished stdin task at most the existing
125 ms drain grace before aborting and joining it. Normal stdin still drains
fully without an arbitrary completion timeout.

## Spool ownership and permissions

`PendingSpool` removes stdout because it owns stdout after construction, but it
removes stderr only when the optional stderr file is present. A deterministic
partial-construction regression protects a pre-existing stderr collision while
confirming the owned stdout file is removed.

Each `create_new` file is explicitly changed to mode 0600 through its open file
handle before use. A child test launched through `/bin/sh` under umask 0777
avoids process-global umask races and proves exact modes plus successful paging.

## Phase-bound status-255 classification

Canonical stderr text is not sufficient to prove a transport failure after a
user command starts, because that command can emit the same text and explicitly
exit 255. The bounded scanner remains unchanged, but its signals are consumed
only for status 255 in bootstrap phases: local `ssh -G` resolution and the fixed
capability probe. Other statuses are never reclassified from these signals.

Every command-phase status 255 is a fixed-message, nonretryable `RemoteExit`,
including exact host-key, authentication, and connection-timeout lines. Its
`remote_process_may_continue` detail is conservatively true because the runner
cannot distinguish an explicit remote exit from a connection interruption. A
fixture matrix proves bootstrap typed errors separately from successful-probe
sh, Bash, and Login command spoof cases. No protocol marker is added.

## Verification

Each behavior is introduced through a failing regression before production
changes. Final gates are formatting, strict all-target clippy, focused SSH
transport tests, all targets and features, and Git diff checks.
