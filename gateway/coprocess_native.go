// +build coprocess
// +build !grpc

package gateway

/*
#cgo python CFLAGS: -DENABLE_PYTHON
#include <stdio.h>
#include <stdlib.h>

#include "../coprocess/api.h"

#ifdef ENABLE_PYTHON
#include "../coprocess/python/dispatcher.h"
#include "../coprocess/python/binding.h"
#endif

*/
import "C"

import (
	"errors"

	"github.com/golang/protobuf/proto"

	"github.com/TykTechnologies/tyk/coprocess"

	"encoding/json"
	"unsafe"
)

// Dispatch prepares a CoProcessMessage, sends it to the GlobalDispatcher and gets a reply.
func (c *CoProcessor) Dispatch(object *coprocess.Object) (*coprocess.Object, error) {
	if GlobalDispatcher == nil {
		return nil, errors.New("Dispatcher not initialized")
	}

	var objectMsg []byte
	var err error
	switch MessageType {
	case coprocess.ProtobufMessage:
		objectMsg, err = proto.Marshal(object)
	case coprocess.JsonMessage:
		objectMsg, err = json.Marshal(object)
	}
	if err != nil {
		return nil, err
	}

	objectMsgStr := string(objectMsg)

	CObjectStr := C.CString(objectMsgStr)

	objectPtr := (*C.struct_CoProcessMessage)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_CoProcessMessage{}))))
	objectPtr.p_data = unsafe.Pointer(CObjectStr)
	objectPtr.length = C.int(len(objectMsg))

	newObjectPtr := (*C.struct_CoProcessMessage)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_CoProcessMessage{}))))

	// Call the dispatcher (objectPtr is freed during this call):
	if err = GlobalDispatcher.Dispatch(unsafe.Pointer(objectPtr), unsafe.Pointer(newObjectPtr)); err != nil {
		return nil, err
	}
	newObjectBytes := C.GoBytes(newObjectPtr.p_data, newObjectPtr.length)

	newObject := &coprocess.Object{}

	switch MessageType {
	case coprocess.ProtobufMessage:
		err = proto.Unmarshal(newObjectBytes, newObject)
	case coprocess.JsonMessage:
		err = json.Unmarshal(newObjectBytes, newObject)
	}
	if err != nil {
		return nil, err
	}

	// Free the returned object memory:
	C.free(unsafe.Pointer(newObjectPtr.p_data))
	C.free(unsafe.Pointer(newObjectPtr))

	return newObject, nil
}
