# Osutil Requirements Evidence

<!-- documents SYS-REQ-098 -->
<!-- documents SYS-REQ-099 -->
<!-- documents SYS-REQ-100 -->
<!-- documents SYS-REQ-101 -->
<!-- documents SYS-REQ-102 -->

This document records the proof scope expansion into `internal/osutil`.

`SYS-REQ-098` covers creating a scoped root from an existing directory.

`SYS-REQ-099` covers rejecting root paths that cannot be absolutized, cannot be statted, or are not directories.

`SYS-REQ-100` covers resolving in-root relative paths.

`SYS-REQ-101` covers rejecting lexical traversal and sibling-prefix escape paths.

`SYS-REQ-102` covers applying write, remove, and stat operations only after scoped validation and keeping those operations confined to the root. Symlink-following escape behavior is tracked separately by `KI-OSUTIL-SYMLINK-ESCAPE`.
