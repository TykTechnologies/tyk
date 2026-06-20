# Gateway Analytics Requirements Evidence

<!-- documents STK-REQ-050 SYS-REQ-138 SW-REQ-125 -->

`STK-REQ-050`, `SYS-REQ-138`, and `SW-REQ-125` cover local gateway
analytics handler and helper behavior in `gateway/analytics.go` plus the
selected request-header tag helper used by success and error analytics paths.

The evidence scope includes:

- analytics handler initialization, worker start/stop/flush lifecycle, and
  serializer selection
- buffered analytics record append to the configured analytics storage key
- status-code and detailed request/response preservation in stored records
- latency, cache, upstream-timeout, API-key, and de-chunked response metadata
  covered by the existing gateway analytics tests
- local GeoIP lookup behavior for empty, valid, and malformed address inputs
- URL normalization for UUID, ULID, numeric, and configured custom fragments
- selected request-header tag expansion while preserving existing tags and
  ignoring non-configured headers

This evidence intentionally does not claim Redis durability beyond the local
configured storage append call, Pump ingestion, dashboard delivery, external
GeoIP database correctness, network transport behavior, or final
client-visible responses.

