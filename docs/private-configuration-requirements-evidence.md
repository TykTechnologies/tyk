# Private Configuration Requirements Evidence

<!-- documents STK-REQ-031 SYS-REQ-119 SW-REQ-106 -->

`STK-REQ-031`, `SYS-REQ-119`, and `SW-REQ-106` cover local
`config/private.go` OAuth token purge interval helper behavior.

The executable evidence is `config/private_test.go`. It covers the one-hour
default duration when no private purge interval is configured and configured
second-based durations when a private purge interval is present.

This evidence does not claim OAuth token storage, purge execution, scheduler
behavior, customer JSON exposure, or final gateway runtime behavior.
