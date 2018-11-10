/*
Package gorpc provides simple RPC API for highload projects.

Gorpc has the following features:

  * Easy-to-use API.
  * Optimized for high load (>10K qps).
  * Uses as low network bandwidth as possible.
  * Minimizes the number of TCP connections in TIME_WAIT and WAIT_CLOSE states.
  * Minimizes the number of send() and recv() syscalls.
  * Provides ability to use arbitrary underlying transport.
    By default TCP is used, but TLS and UNIX sockets are already available.

*/
package gorpc
