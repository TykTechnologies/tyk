<!-- documents STK-REQ-078 SYS-REQ-166 SW-REQ-153 -->

`STK-REQ-078`, `SYS-REQ-166`, and `SW-REQ-153` cover local gateway API loader
internal-handler lookup behavior in `gateway/api_loader.go`.

The executable evidence is `gateway/api_loader_reqproof_test.go`. It verifies
that `findInternalHttpHandlerByNameOrID` reports not found for a tested missing
API, reports not found for a tested matching API without a registered handler,
and returns the matching API plus registered handler for tested API ID and
loop-name lookups.

This evidence does not claim internal proxy routing, handler execution, route
generation, middleware execution, upstream connectivity, distributed
synchronization, or final client responses.
