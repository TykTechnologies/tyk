// Copyright © 2015 Clement 'cmc' Rey <cr.rey.clement@gmail.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

/*
The GAS library provides auto-reconnecting TCP sockets in a
tiny, fully tested, thread-safe API.

The `TCPClient` struct embeds a `net.TCPConn` and overrides
its `Read()` and `Write()` methods, making it entirely compatible
with the `net.Conn` interface and the rest of the `net` package.
This means you should be able to use this library by just
replacing `net.Dial` with `gas.Dial` in your code.

To test the library, you can run a local TCP server with:

    $ ncat -l 9999 -k

and run this code:

    package main

    import (
        "log"
        "time"

        "github.com/teh-cmc/goautosocket"
    )

    func main() {
        // connect to a TCP server
        conn, err := gas.Dial("tcp", "localhost:9999")
        if err != nil {
            log.Fatal(err)
        }

        // client sends "hello, world!" to the server every second
        for {
            _, err := conn.Write([]byte("hello, world!\n"))
            if err != nil {
                // if the client reached its retry limit, give up
                if err == gas.ErrMaxRetries {
                    log.Println("client gave up, reached retry limit")
                    return
                }
                // not a GAS error, just panic
                log.Fatal(err)
            }
            log.Println("client says hello!")
            time.Sleep(time.Second)
        }
    }

Then try to kill and reboot your server, the client will automatically reconnect and start sending messages again; unless it has reached its retry limit.
*/
package gas
