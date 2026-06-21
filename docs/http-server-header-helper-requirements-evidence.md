<!-- documents STK-REQ-085 SYS-REQ-173 SW-REQ-160 -->

`STK-REQ-085`, `SYS-REQ-173`, and `SW-REQ-160` cover local HTTP server and
header helper behavior in `internal/httputil`.

The executable evidence is `internal/httputil/connection_watcher_test.go` and
`internal/httputil/headers_test.go`. It covers zero initial connection watcher
counts, explicit positive and negative count deltas, connection-state deltas for
new, closed, and hijacked connections, ignored non-counting connection states,
current count reporting, and Basic Authorization header construction for tested
username and password pairs.

This evidence does not claim nonnegative connection-count enforcement, full
server lifecycle management, upstream authentication, credential validation,
transport security, analytics, persistence, or final client responses.
