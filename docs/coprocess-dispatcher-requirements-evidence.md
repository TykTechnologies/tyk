# Coprocess Dispatcher Requirements Evidence

<!-- documents STK-REQ-036 SYS-REQ-124 SW-REQ-111 -->

`STK-REQ-036`, `SYS-REQ-124`, and `SW-REQ-111` cover local
`coprocess.Dispatcher` interface availability.

The executable evidence is `coprocess/dispatcher_reqproof_test.go`. It uses a
compile-time interface conformance assertion and a table-driven test that calls
the dispatcher methods through the interface.

This evidence does not claim gRPC transport behavior, Python runtime loading,
Lua bundle execution, gateway middleware effects, generated protobuf
serialization behavior, or downstream dispatcher implementation correctness.
