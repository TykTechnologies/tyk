<!-- documents STK-REQ-091 SYS-REQ-179 SW-REQ-166 -->

`STK-REQ-091`, `SYS-REQ-179`, and `SW-REQ-166` cover local TCP proxy behavior
in the `tcp` package.

The executable evidence is `tcp/tcp_test.go`. It covers local domain handler
configuration, handler replacement and removal, single-target and TLS SNI
target selection, fallback target selection, request and response modifier
application, stat flushing, stats callbacks during a proxied connection,
shutdown context setup and timeout behavior, active connection tracking,
connection endpoint formatting, closed-socket error classification, and pipe
termination for shutdown, modifier, read, write, and empty-payload paths.

This evidence does not claim production listener lifecycle integration,
arbitrary TLS certificate validation, upstream availability, load-balancing,
analytics delivery, end-to-end gateway API admission, or final client-visible
behavior beyond the focused TCP proxy tests.
