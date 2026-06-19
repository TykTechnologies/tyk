# internal/cache Requirements Evidence

<!-- documents STK-REQ-021 -->
<!-- documents SYS-REQ-109 -->
<!-- documents SW-REQ-029 -->
<!-- documents SW-REQ-035 -->

This slice covers in-process cache helper behavior in `internal/cache` and the
local DNS cache storage wrapper in `dnscache`.
It is limited to local TTL cache storage and retrieval, item expiration,
item snapshots, delete, cleanup, count, flush, close, repository delegation,
default timeout handling, janitor cleanup or close behavior, and DNS lookup
result caching in local storage.

It does not claim distributed cache behavior, persistence, Redis or other
external storage semantics, DNS dialer behavior, caller cache-key policy,
cross-process consistency, or gateway endpoint outcomes.

`STK-REQ-021` captures the cache-caller need for deterministic local cache
operations. `SYS-REQ-109` describes the helper behavior expected from the cache
component. `SW-REQ-029` owns the implementation in `internal/cache`.

Evidence in `internal/cache` tests covers construction, set/get, missing
lookup, default timeout delegation, expiration boundaries, item snapshots that
omit expired entries, cleanup deletion, count, delete, flush, close, janitor
cleanup execution, and repeated or concurrent janitor close calls.

`SW-REQ-035` owns the concrete `dnscache` storage wrapper behavior. Evidence in
`dnscache` tests covers local storage construction, address-list set/get/list,
delete, clear, empty-host lookup rejection, and successful DNS lookup caching.
It does not claim DNS dialer wrapping, DNS server availability, resolver
correctness, failed DNS lookup classification, multi-IP selection strategy,
network connection behavior, distributed cache behavior, persistence, caller
cache-key policy, cross-process consistency, or gateway endpoint outcomes.
