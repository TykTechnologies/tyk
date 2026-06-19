# internal/maps Requirements Evidence

<!-- documents STK-REQ-022 -->
<!-- documents SYS-REQ-110 -->
<!-- documents SW-REQ-030 -->

This slice covers in-process map helper behavior in `internal/maps`.
It is limited to flattening supported nested values into dotted string keys,
unsupported-value errors, non-string map-key panics, and synchronized string-map
set/get operations.

It does not claim API definition schema conversion, caller validation policy
before flattening, persistence, cross-process sharing, or gateway endpoint
outcomes.

`STK-REQ-022` captures the helper-caller need for deterministic map operations.
`SYS-REQ-110` describes the map helper behavior. `SW-REQ-030` owns the
implementation in `internal/maps`.

Evidence in `internal/maps` tests covers nested map, slice, array, struct,
boolean, integer, float, string, and nil flattening; unsupported channel values;
non-string map-key panics; string-map set/get and missing-key results; and
race-free concurrent string-map access under `go test -race`.
