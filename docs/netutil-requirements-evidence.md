# Netutil Requirements Evidence

<!-- documents SYS-REQ-095 -->
<!-- documents SYS-REQ-096 -->
<!-- documents SYS-REQ-097 -->
<!-- documents SW-REQ-005 -->

This document records the proof scope expansion into gateway node network
identity behavior and the `internal/netutil` software helper that implements it.

`SYS-REQ-095` covers gateway node address discovery reporting usable IPv4 and
IPv6 non-loopback interface addresses when such addresses are available.

`SYS-REQ-096` covers gateway node address discovery excluding loopback,
non-IPNet, malformed, and non-convertible interface address records from the
reported node address list.

`SYS-REQ-097` covers propagation of interface enumeration errors so callers can
distinguish failure from an empty successful result.

`SW-REQ-005` owns the concrete `internal/netutil.GetIpAddress` helper behavior:
return non-loopback IPv4 and IPv6 addresses in enumeration order, filter
unusable address records, return an empty successful result when no usable
addresses exist, and return the underlying enumeration error on failure.
