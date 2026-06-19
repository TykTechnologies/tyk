# Sanitize Requirements Evidence

<!-- documents SYS-REQ-091 -->
<!-- documents SYS-REQ-092 -->
<!-- documents SYS-REQ-093 -->
<!-- documents SYS-REQ-094 -->

This document records the proof scope expansion into `internal/sanitize`.

`SYS-REQ-091` covers acceptance of archive paths that resolve inside the target directory.

`SYS-REQ-092` covers rejection of unsafe archive paths, including absolute, volume-qualified, traversal, and unresolvable paths.

`SYS-REQ-093` covers acceptance of safe single path components after bounded URL decoding.

`SYS-REQ-094` covers rejection of unsafe path components, including empty, dot, dot-dot, separator-containing, encoded traversal, encoded separator, and malformed encoded components.
