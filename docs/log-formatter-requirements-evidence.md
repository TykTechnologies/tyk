<!-- documents STK-REQ-088 SYS-REQ-176 SW-REQ-163 -->

`STK-REQ-088`, `SYS-REQ-176`, and `SW-REQ-163` cover local logging formatter
helper behavior in `log`.

The executable evidence is `log/log_test.go`. It covers default, JSON, and
registered formatter selection; fallback to the default formatter for unknown
format names; environment-derived global formatter and level setup; raw logger
message formatting; JSON formatter preservation of error values, optional
`logrus_error` output, nested `DataKey` fields, optional timestamp omission,
message and level fields; and translation formatter wrapping plus string-code
message translation and passthrough for untranslated string codes.

This evidence does not claim log delivery, external sink behavior, global logger
thread-safety, middleware execution, non-string translation code handling,
complete log schema compatibility, or final client responses.
`KI-LOG-TRANSLATION-NONSTRING-CODE-PANIC` tracks the current product defect where
translation formatting can panic when the `code` field is not a string.
