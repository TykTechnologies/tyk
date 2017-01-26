/*

Streaming example:

  $ redis-cli -p 9736 ping
  PONG

  $ redis-cli -p 9736 file
  (error) ERR wrong number of arguments for 'file' command
  $ redis-cli -p 9736 file bad.txt
  (error) ERR no such file or directory

  $ echo -n "it works!" > /tmp/hi.txt
  $ redis-cli -p 9736 file hi.txt
  "it works!"

*/
package main

import (
	"log"
	"net/http"
	"path"

	"github.com/bsm/redeo"
)

var root = http.Dir("/tmp")

func pingCmd(out *redeo.Responder, _ *redeo.Request) error {
	out.WriteInlineString("PONG")
	return nil
}

func fileCmd(out *redeo.Responder, req *redeo.Request) error {
	if len(req.Args) != 1 {
		return req.WrongNumberOfArgs()
	}

	file, err := root.Open(path.Clean(req.Args[0]))
	if err != nil {
		return err
	}

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	out.WriteN(file, stat.Size())
	return nil
}

func main() {
	srv := redeo.NewServer(nil)

	srv.HandleFunc("ping", pingCmd)
	srv.HandleFunc("file", fileCmd)

	log.Printf("Listening on tcp://%s", srv.Addr())
	log.Fatal(srv.ListenAndServe())
}
