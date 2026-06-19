# internal/cache Requirements Evidence

<!-- documents STK-REQ-021 -->
<!-- documents SYS-REQ-109 -->
<!-- documents SW-REQ-029 -->

This slice covers in-process cache helper behavior in `internal/cache`.
It is limited to local TTL cache storage and retrieval, item expiration,
item snapshots, delete, cleanup, count, flush, close, repository delegation,
default timeout handling, and janitor cleanup or close behavior.

It does not claim distributed cache behavior, persistence, Redis or other
external storage semantics, caller cache-key policy, cross-process consistency,
or gateway endpoint outcomes.

`STK-REQ-021` captures the cache-caller need for deterministic local cache
operations. `SYS-REQ-109` describes the helper behavior expected from the cache
component. `SW-REQ-029` owns the implementation in `internal/cache`.

Evidence in `internal/cache` tests covers construction, set/get, missing
lookup, default timeout delegation, expiration boundaries, item snapshots that
omit expired entries, cleanup deletion, count, delete, flush, close, janitor
cleanup execution, and repeated or concurrent janitor close calls.
