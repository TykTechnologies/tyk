<!-- documents STK-REQ-079 SYS-REQ-167 SW-REQ-154 -->

`STK-REQ-079`, `SYS-REQ-167`, and `SW-REQ-154` cover local gateway API loader
explicit-route subpath wrapper behavior in `gateway/api_loader.go`.

The executable evidence is `gateway/api_loader_reqproof_test.go`. It verifies
that `explicitRouteSubpaths` preserves the original handler when wrapping is
disabled, when a prefix already ends with a slash, and when a prefix contains a
route parameter. It also verifies that the local wrapper delegates exact-prefix
and nested subpath requests while returning `404 Not Found` for sibling and
outside paths.

This evidence does not claim full route generation, middleware execution,
upstream connectivity, distributed synchronization, or final client responses
beyond the local wrapper output.
