# UUID Requirements Evidence

<!-- documents SYS-REQ-083 -->
<!-- documents SW-REQ-001 -->

This document records the identifier proof slice and its software decomposition into `internal/uuid`.

`SYS-REQ-083` covers gateway identifier behavior: dashed UUID generation, dash-free UUID generation, UUID validation acceptance/rejection, and loud failure when identifier generation reports an internal error.

`SW-REQ-001` owns the `internal/uuid` package behavior that implements `SYS-REQ-083`.
