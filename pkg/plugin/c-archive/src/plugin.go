package main

//#include <stdlib.h>
//#include "plugin.h"
import "C"

import (
	"fmt"
	"log"

	"bufio"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"plugin"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

func main() {}

var (
	// mu protects access to globals
	mu sync.Mutex

	// keyIndex is an incremental symbol ID
	keyIndex int32

	handlers map[string]http.Handler
	symbols  []S
)

//export Load
func Load(namespace *C.char, name *C.char) C.int {
	defer func() {
		C.free(unsafe.Pointer(namespace))
		C.free(unsafe.Pointer(name))
	}()

	return C.int(load(C.GoString(namespace), C.GoString(name)))
}

type S struct {
	id        int
	namespace string
	name      string
}

func newSymbol(namespace string, name string) S {
	id := atomic.AddInt32(&keyIndex, 1)
	return S{
		id:        int(id),
		namespace: namespace,
		name:      name,
	}
}

func load(namespace string, name string) int {
	log.Printf("load %s, %s", namespace, name)

	mu.Lock()
	defer mu.Unlock()

	for _, symbol := range symbols {
		if symbol.namespace == namespace && symbol.name == name {
			return symbol.id
		}
	}

	item := newSymbol(namespace, name)
	symbols = append(symbols, item)
	return item.id
}

func find(id int) *S {
	mu.Lock()
	defer mu.Unlock()

	for k, symbol := range symbols {
		if symbol.id == id {
			return &symbols[k]
		}
	}
	return nil
}

func result_error(err error) C.result {
	cErr := C.CString(err.Error())
	defer C.free(unsafe.Pointer(cErr))

	return C.result_error(cErr)
}

func result_success(response string) C.result {
	cResp := C.CString(response)
	defer C.free(unsafe.Pointer(cResp))

	return C.result_success(cResp)
}

//export Invoke
func Invoke(fd C.int, requestBytes *C.char) C.result {
	ctx := find(int(fd))
	if ctx == nil {
		return result_error(errors.New("invalid fd"))
	}

	req := C.GoString(requestBytes)

	log.Printf("invoke %s, %s\nrequest:\n%s", ctx.namespace, ctx.name, req)

	result, err := invoke(ctx, req)
	if err != nil {
		return result_error(err)
	}
	return result_success(string(result))
}

func invoke(symbol *S, requestString string) ([]byte, error) {
	var (
		req *http.Request
		err error
	)

	if requestString != "" {
		buf := bufio.NewReader(strings.NewReader(requestString))

		req, err = http.ReadRequest(buf)
		if err != nil {
			return nil, fmt.Errorf("error decoding request: %w", err)
		}
	}

	h, err := handler(symbol.namespace, symbol.name)
	if err != nil {
		return nil, fmt.Errorf("error invoking handler: %w", err)
	}

	recorder := httptest.NewRecorder()

	h(recorder, req)

	response := recorder.Result()

	responseBytes, err := httputil.DumpResponse(response, true)
	if err != nil {
		return nil, fmt.Errorf("error dumping response: %w", err)
	}

	log.Println("responseBytes", string(responseBytes))
	return responseBytes, nil
}

//export Free
func Free(fd C.int) C.int {
	find(int(fd))
	return 0
}

func loadPlugin(modulePath string, symbol string) (interface{}, error) {
	loadedPlugin, err := plugin.Open(modulePath)
	if err != nil {
		return nil, err
	}
	return loadedPlugin.Lookup(symbol)
}

func handler(modulePath string, symbol string) (http.HandlerFunc, error) {
	funcSymbol, err := loadPlugin(modulePath, symbol)
	if err != nil {
		return nil, err
	}

	// try to cast symbol to real func
	pluginHandler, ok := funcSymbol.(func(http.ResponseWriter, *http.Request))
	if !ok {
		return nil, errors.New("could not cast function symbol to http.HandlerFunc")
	}
	return pluginHandler, nil
}
