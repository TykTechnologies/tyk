# Rate Requirements Evidence

<!-- documents SYS-REQ-103 -->
<!-- documents SW-REQ-006 -->
<!-- documents SW-REQ-009 -->
<!-- documents SW-REQ-010 -->
<!-- documents SW-REQ-011 -->
<!-- documents SW-REQ-012 -->
<!-- documents SW-REQ-013 -->
<!-- documents SW-REQ-014 -->
<!-- documents SW-REQ-015 -->
<!-- documents SW-REQ-016 -->
<!-- documents SW-REQ-017 -->
<!-- documents SW-REQ-018 -->
<!-- documents SW-REQ-031 -->

This document records the current rate-limit support-state proof slice. The
slice is deliberately limited to the listed `internal/rate/model` allowance
state behavior, dependency-free `internal/rate` support helpers, header senders,
facade helpers, smoothing orchestration, and local `internal/memorycache`
leaky-bucket storage.

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
for quota and rate-limit state metadata plus the shared `header` package names
used by that sender. Its evidence covers sender selection, quota no-op behavior
on rate-limit calls, zero quota headers for nil sessions, int64-preserving quota
header serialization, quota header clearing on the rate-limit sender quota path,
Unix reset formatting, and negative remaining clamping. It does not claim the
full gateway middleware lifecycle, quota-blocked response behavior, or upstream
header interaction beyond the local sender.

`SW-REQ-012` owns the concrete `internal/rate` smoothing orchestration and
arithmetic behavior. Its evidence covers configuration rejection, initial
allowance creation, hold-off skips, lock errors, set errors, increase and
decrease transitions with emitted direction events, no-change paths, and the
increase/decrease boundary arithmetic. It uses mock allowance storage evidence
and does not claim live Redis availability, distributed lock correctness beyond
error propagation, external limiter algorithm correctness, or gateway admission.

`SW-REQ-013` owns the concrete `internal/rate` checker helper behavior. Its
evidence covers empty stats, strict greater-than blocking semantics, and
anonymous checker delegation including error propagation. It does not claim
limiter selection, Redis command behavior, limiter algorithm correctness,
distributed locking, or gateway admission.

`SW-REQ-014` owns the concrete `internal/rate` root-package allowance alias and
constructor facade. Its evidence covers alias compatibility and constructor
forwarding to the underlying allowance model. It does not claim allowance model
behavior beyond the underlying `SW-REQ-006` evidence, Redis storage behavior, or
gateway admission.

`SW-REQ-015` owns the concrete `internal/rate` limiter facade and key
construction behavior. Its evidence covers release-build limiter selection for
fixed-window mode, nil limiter behavior when no supported limiter is enabled,
and limiter key construction from cached session hashes or supplied keys. It
does not claim Redis command behavior, limiter algorithm correctness,
distributed locking, or gateway admission.

`SW-REQ-016` owns the concrete `internal/rate` storage client construction and
TLS configuration mapping behavior. Its evidence covers local Redis option
propagation, simple/cluster/sentinel selection precedence, default pool and
timeout behavior, external-services mTLS precedence over legacy storage TLS
settings, certificate loading success and failure paths, and TLS version
parsing. It does not claim Redis server availability, successful network
dialing, Redis command behavior, limiter algorithm correctness, or gateway
admission.

`SW-REQ-017` owns the concrete `internal/rate` sliding-log storage
orchestration and Redis sorted-set/script mapping behavior. Its evidence covers
constructor validation, pipeline and transaction dispatch, pipeline error
propagation, Redis sorted-set trim/count/member flows, unique members for
same-timestamp hits, script-derived count/remaining/reset stats, smoothing
delegation after successful script execution, and fail-closed behavior on script
errors. It does not claim distributed Redis topology correctness, external
limiter algorithm correctness, gateway admission, or product cooldown policy.

`SW-REQ-018` owns the concrete `internal/rate/limiter` adapter wiring behavior.
Its evidence covers adapter construction defaults, no-op local locking,
Redis-backed locking, local and Redis-backed first-call delegation for
fixed-window, sliding-window, token-bucket, and leaky-bucket adapters, and
fixed-window exhaustion error propagation. It does not claim correctness of the
external limiter algorithms, distributed lock robustness, Redis server
availability outside provisioned tests, or gateway admission.

`SW-REQ-031` owns the concrete `internal/memorycache` local leaky-bucket storage
used by gateway rate-limit allowance checks. Its evidence covers bucket
capacity decrement, full-bucket rejection, state reporting, interval reset,
named bucket reuse through storage creation, synchronized TTL cache set/get and
count behavior, and cleanup-context cancellation clearing cached buckets. It
does not claim gateway admission decisions, distributed limiter correctness,
Redis behavior, cross-process synchronization, caller key selection, response
headers, or external limiter algorithms.
