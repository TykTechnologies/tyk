# Compression Requirements Evidence

<!-- documents SYS-REQ-085 -->
<!-- documents SYS-REQ-086 -->
<!-- documents SYS-REQ-087 -->
<!-- documents SYS-REQ-088 -->
<!-- documents SYS-REQ-089 -->
<!-- documents SYS-REQ-090 -->

This document records the proof scope expansion into `internal/compression`.

`SYS-REQ-085` covers valid Zstd round-trip byte preservation and frame output.

`SYS-REQ-086` covers invalid or malformed compressed-frame rejection and magic-prefix detection.

`SYS-REQ-087` covers rejection of decoded payloads over the active decompressed-size limit.

`SYS-REQ-088` covers successful decompression when decoded payloads are within the active decompressed-size limit.

`SYS-REQ-089` covers clamping decompressed-size configuration updates to the package minimum limit.

`SYS-REQ-090` covers fail-closed behavior for unavailable, wrong-type, or failing internal Zstd codec pool entries.
