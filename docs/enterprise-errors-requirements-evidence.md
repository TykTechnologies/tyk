# Enterprise Errors Requirements Evidence

<!-- documents STK-REQ-038 SYS-REQ-126 SW-REQ-113 -->

`STK-REQ-038`, `SYS-REQ-126`, and `SW-REQ-113` cover local `ee/errors.go`
enterprise sentinel error behavior.

The executable evidence is `ee/errors_reqproof_test.go`. It verifies that
`ErrActionNotAllowed` is non-nil, retains the expected message, and remains
comparable through `errors.Is`.

This evidence does not claim stream middleware behavior, upstream
authentication behavior, license enforcement behavior, or final gateway request
handling.
