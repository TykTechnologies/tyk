// +build coprocess
// +build !python

package main

/*
#include <stdio.h>
#include <stdlib.h>

#include "coprocess/sds/sds.h"

#include "coprocess/api.h"

static int TestMessageLength(struct CoProcessMessage* object) {
	return object->length;
}

static struct CoProcessMessage* TestDispatchHook(struct CoProcessMessage* object) {
	struct CoProcessMessage* outputObject = malloc(sizeof *outputObject);
	printf("TestDispatchHook %s\n", object->p_data);
  return object;
};

*/
import "C"

import(
	"unsafe"
	"github.com/golang/protobuf/proto"
	"github.com/TykTechnologies/tyk/coprocess"
	"fmt"
)

type TestDispatcher struct {
	coprocess.Dispatcher
}

/* Basic CoProcessDispatcher functions */

func (d *TestDispatcher) Dispatch(objectPtr unsafe.Pointer) unsafe.Pointer {
	var newObjectPtr *C.struct_CoProcessMessage
	newObjectPtr = C.TestDispatchHook(objectPtr)

	return unsafe.Pointer(newObjectPtr)
}

func (d *TestDispatcher) DispatchEvent(eventJSON []byte) {
	/*
	var CEventJSON *C.char
	CEventJSON = C.CString(string(eventJSON))
	C.Python_DispatchEvent(CEventJSON)
	C.free(unsafe.Pointer(CEventJSON))
	*/
	return
}

func (d *TestDispatcher) Reload() {
	// C.Python_ReloadDispatcher()
}

/* General test helpers */

func NewTestDispatcher() (dispatcher *TestDispatcher, err error) {
	d := &TestDispatcher{}
	return d, nil
}

func (d *TestDispatcher) ToCoProcessMessage(object *coprocess.Object) unsafe.Pointer {
	  objectMsg, _ := proto.Marshal(object)
		fmt.Println("MARSHAL", objectMsg)
	  objectMsgStr := string(objectMsg)

	  var CObjectStr *C.char
	  CObjectStr = C.CString(objectMsgStr)

	  var messagePtr *C.struct_CoProcessMessage

	  messagePtr = (*C.struct_CoProcessMessage)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_CoProcessMessage{}))))
	  messagePtr.p_data = unsafe.Pointer(CObjectStr)
	  messagePtr.length = C.int(len(objectMsg))

		return unsafe.Pointer(messagePtr)
}

func (d *TestDispatcher) ToCoProcessObject(messagePtr unsafe.Pointer) *coprocess.Object {
	var message *C.struct_CoProcessMessage
	message = (*C.struct_CoProcessMessage)(messagePtr)

	var object *coprocess.Object
	object = &coprocess.Object{}

	objectBytes := C.GoBytes(message.p_data, message.length)

	proto.Unmarshal(objectBytes, object)

	return object
}

func (d *TestDispatcher) TestMessageLength(messagePtr unsafe.Pointer) (length int) {
	var message *C.struct_CoProcessMessage
	message = (*C.struct_CoProcessMessage)(messagePtr)

	length = int(C.TestMessageLength(message))

	return length
}
