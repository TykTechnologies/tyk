# Dynamic Python Loader Requirements Evidence

<!-- documents STK-REQ-048 SYS-REQ-136 SW-REQ-123 -->

`STK-REQ-048`, `SYS-REQ-136`, and `SW-REQ-123` cover only local `dlpython`
loader helper behavior.

The executable evidence is `dlpython/main_test.go` and
`dlpython/version_test.go`. The tests create fake `python-config` executables
and a fake dynamic Python library that exports the C API symbols used by the
package. This lets the tests exercise version selection, library-path parsing,
dynamic symbol mapping, runtime initialization forwarding, Python path setup,
and representative object/tuple/bytes/module helper wrappers without relying on
a machine-installed Python runtime.

This evidence does not claim real CPython semantic correctness, Python plugin
execution, gateway coprocess middleware behavior, plugin isolation, filesystem
trust, external Python package availability, gateway request admission,
persistence, analytics, or final client-visible gateway behavior.
