<!-- documents STK-REQ-097 SYS-REQ-185 SW-REQ-172 -->

`STK-REQ-097`, `SYS-REQ-185`, and `SW-REQ-172` cover local dummy storage
behavior in `storage/dummy.go`.

The executable evidence is `storage/dummy_test.go`. It covers the decomposed
local outputs for dummy storage construction, multi-key and raw-key reads, key
set/get/delete behavior, wildcard key deletion and listing, list
append/range/remove behavior, existence checks across data and index maps,
connect success, and explicit panic behavior for methods that are currently
unsupported by DummyStorage.

This evidence does not claim production Redis behavior, persistence, TTL
handling, sorted-set semantics, rolling-window semantics, raw-key mutation,
bulk deletion semantics, concurrency safety, or final client-visible behavior
beyond the focused in-memory dummy storage tests.
