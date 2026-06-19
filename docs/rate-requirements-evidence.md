# Rate Requirements Evidence

<!-- documents SYS-REQ-103 -->
<!-- documents SW-REQ-006 -->
<!-- documents SW-REQ-009 -->
<!-- documents SW-REQ-010 -->
<!-- documents SW-REQ-011 -->

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

`SW-REQ-010` owns the concrete `internal/rate.Prefix` key-fragment normalization
helper used by allowance storage and lock-key construction. Its evidence covers
ordinary joins, empty fragments, dash-wrapped fragments, and separator-only
inputs. It does not claim every gateway rate-limit key scope or endpoint suffix.

`SW-REQ-011` owns the concrete `internal/rate` header-sender support behavior
for quota and rate-limit state metadata. Its evidence covers sender selection,
quota no-op behavior on rate-limit calls, zero quota headers for nil sessions,
int64-preserving quota header serialization, quota header clearing on the
rate-limit sender quota path, Unix reset formatting, and negative remaining
clamping. It does not claim the full gateway middleware lifecycle, quota-blocked
response behavior, or upstream header interaction beyond the local sender.

The rest of the root `internal/rate` package, smoothing orchestration,
sliding-log integration, and `internal/rate/limiter` algorithms are intentionally
not included in this slice. They need separate requirements and evidence before
scope expansion.
