package plugin

/*
#cgo CFLAGS: -I./lib
#cgo LDFLAGS: -L./lib -lplugin -Wl,-rpath=./lib
#include <stdlib.h>
#include "libplugin.h"
#include "plugin.h"
*/
import "C"

import (
	"bufio"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"unsafe"
)

// Handler returns a registered handler for a name/symbol pair. The function
// will return nil in case no such handler is registered.
func Handler(namespace, name string) http.HandlerFunc {
	return handler(namespace, name)
}

func handler(namespace, name string) http.HandlerFunc {
	ctx := C.Load(C.CString(namespace), C.CString(name))

	return func(w http.ResponseWriter, req *http.Request) {
		reqBytes, err := httputil.DumpRequest(req, true)
		if err != nil {
			log.Println(err)
			return
		}

		cReq := C.CString(string(reqBytes))
		defer C.free(unsafe.Pointer(cReq))

		result := C.Invoke(ctx, cReq)
		if result.err != nil {
			msg := C.GoString(result.err)
			log.Println(msg)
			return
		}

		response := C.GoString(result.response)

		log.Println("response:", response)

		if response != "" {
			reader := bufio.NewReader(strings.NewReader(response))
			response, err := http.ReadResponse(reader, req)
			if err != nil {
				log.Println(err)
				return
			}

			responseBody, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Println(err)
				return
			}

			defer response.Body.Close()

			if string(responseBody) != "" {
				w.Write(responseBody)
			}
		}

	}
}
