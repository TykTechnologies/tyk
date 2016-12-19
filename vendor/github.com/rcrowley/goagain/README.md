goagain
=======

Zero-downtime restarts in Go
----------------------------

The `goagain` package provides primitives for bringing zero-downtime restarts to Go applications that accept connections from a [`net.TCPListener`](http://golang.org/pkg/net/#TCPListener) or [`net.UnixListener`](http://golang.org/pkg/net/#UnixListener).

Have a look at the examples because it isn't just a matter of importing the library and everything working.  Your `main` function will have to accomodate the `goagain` protocols and your process will have to have some definition (however contrived you like) of a graceful shutdown process.

Installation
------------

	go get github.com/rcrowley/goagain

Usage
-----

Send `SIGUSR2` to a process using `goagain` and it will restart without downtime.

[`example/single/main.go`](https://github.com/rcrowley/goagain/blob/master/example/single/main.go):  The `Single` strategy (named because it calls `execve`(2) once) operates similarly to Nginx and Unicorn.  The parent forks a child, the child execs, and then the child kills the parent.  This is easy to understand but doesn't play nicely with Upstart and similar direct-supervision `init`(8) daemons.  It should play nicely with `systemd`.

[`example/double/main.go`](https://github.com/rcrowley/goagain/blob/master/example/double/main.go):  The `Double` strategy (named because it calls `execve`(2) twice) is **experimental** so proceed with caution.  The parent forks a child, the child execs, the child signals the parent, the parent execs, and finally the parent kills the child.  This is regrettably much more complicated but plays nicely with Upstart and similar direct-supervision `init`(8) daemons.
