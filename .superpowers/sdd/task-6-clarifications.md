# Task 6 Binding Clarifications

These clarifications supplement the committed Task 6 expanded design and are
binding for implementation and review.

1. An empty non-LF logical record is not representable. The parser rejects
   `Context`, `Remove`, or `Add` records whose payload is empty and whose exact
   no-newline marker would make the serialized logical line zero bytes. This
   closes the zero-byte Create bypass while preserving empty LF-terminated
   lines.
2. No logical record may be emitted after a non-LF output record. If the
   conflict depends on the current base or untouched suffix, it is
   `WriteConflict`; a syntactically impossible patch-side ordering is
   `InvalidArgument`.
3. No-newline finality is side-aware. A marked Remove terminates only the old
   side and may be followed by Add records; a marked Add terminates only the
   new side and may be followed by Remove records. A marked Context terminates
   both. Any later record or hunk affecting a terminated side is invalid.
4. Base logical lines are traversed with a borrowed streaming cursor. The
   implementation must not collect a `Vec<LogicalLine>`; a newline-dense 4 MiB
   base must not amplify into millions of line objects.
5. Unknown-host, read-only, effective patch-size, and parse failures occur
   before a trusted parsed path set exists and leave all four patch-progress
   fields absent. After successful parse, snapshot/application/path failures
   set `changed_paths=[]`, `not_changed_paths` to all parsed paths, and
   `outcome_unknown_paths=[]`; `failed_path` is the path being processed when
   one exists, otherwise absent for host-wide cancellation/limits.
6. Parser boundary tests cover checked `usize` conversion and arithmetic,
   zero anchors, exact/+1 aggregate limits, EOF framing, byte-counted UTF-8
   paths, and CRLF. CR is data only in hunk payload; it is rejected in every
   syntax record. A CRLF base requires a payload containing the matching CR.
7. An Update whose removal and addition serialize to identical bytes is
   valid syntax but application returns `WriteConflict` because it proves no
   content change and should not trigger a guarded remote rewrite.
8. Task 4 snapshot admission uses the minimum of the compiled patch ceiling,
   the host effective `max_write_bytes`, and the fixed runner's safe output
   ceiling. A larger complete base is rejected before transfer; snapshot never
   substitutes the public truncating read API.
