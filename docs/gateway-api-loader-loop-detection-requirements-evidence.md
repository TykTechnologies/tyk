<!-- documents STK-REQ-077 SYS-REQ-165 SW-REQ-152 -->

`STK-REQ-077`, `SYS-REQ-165`, and `SW-REQ-152` cover local gateway API loader
loop-detection behavior in `gateway/api_loader.go`.

The executable evidence is `gateway/api_loader_reqproof_test.go`. It verifies
that `isLoop` ignores a tested non-tyk request scheme, identifies tested
tyk-scheme requests as loops, allows loop levels at configured limits, and
reports errors when loop levels exceed default or explicit limits.

This evidence does not claim internal proxy routing, loop request dispatch,
middleware execution, upstream connectivity, distributed synchronization, or
final client responses.
