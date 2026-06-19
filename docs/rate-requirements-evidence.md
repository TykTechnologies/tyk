# Rate Requirements Evidence

<!-- documents SYS-REQ-103 -->
<!-- documents SW-REQ-006 -->
<!-- documents SW-REQ-009 -->

This document records the first rate-limit support-state proof slice. The slice
is deliberately limited to `internal/rate/model` allowance state behavior and
the dependency-free allowance store behavior in `internal/rate`.

`SYS-REQ-103` covers gateway rate-limit allowance state operations at the
system layer.

`SW-REQ-006` owns the concrete `internal/rate/model.Allowance` implementation
that constructs allowance state, decodes stored fields, exports stored fields,
validates timing, resets mutable state, exposes delay and current allowance
values, updates the current allowance, computes the next update time, and
reports expiry.

`SW-REQ-009` owns the concrete `internal/rate.AllowanceStore` support behavior
that constructs a store, creates lock objects with allowance lock keys, reads
stored allowance fields, caches decoded allowance state, writes allowance fields,
sets expiry from the allowance delay, and preserves the written allowance in the
local cache. Its evidence uses redismock and local cache assertions; it does not
claim live Redis availability, distributed lock correctness, sliding-log
correctness, external limiter algorithm behavior, or gateway request admission.

The rest of the root `internal/rate` package, smoothing orchestration,
sliding-log integration, and `internal/rate/limiter` algorithms are intentionally
not included in this slice. They need separate requirements and evidence before
scope expansion.
