# Rate Requirements Evidence

<!-- documents SYS-REQ-103 -->
<!-- documents SW-REQ-006 -->

This document records the first rate-limit support-state proof slice. The slice
is deliberately limited to `internal/rate/model` allowance state behavior.

`SYS-REQ-103` covers gateway rate-limit allowance state operations at the
system layer.

`SW-REQ-006` owns the concrete `internal/rate/model.Allowance` implementation
that constructs allowance state, decodes stored fields, exports stored fields,
validates timing, resets mutable state, exposes delay and current allowance
values, updates the current allowance, computes the next update time, and
reports expiry.

The root `internal/rate` package, Redis storage, smoothing orchestration,
sliding-log integration, and `internal/rate/limiter` algorithms are intentionally
not included in this slice. They need separate requirements and evidence before
scope expansion.
