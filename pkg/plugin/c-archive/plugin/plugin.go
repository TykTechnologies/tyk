package main

import (
	"net/http"
)

func main() {}

func MyHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}
