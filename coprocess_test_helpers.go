// +build coprocess
// +build !python

package main

/*
#include <stdio.h>
#include <stdlib.h>

#include "coprocess/sds/sds.h"

#include "coprocess/api.h"

void applyTestHooks();

static int TestMessageLength(struct CoProcessMessage* object) {
	return object->length;
}

static struct CoProcessMessage* TestDispatchHook(struct CoProcessMessage* object) {
	struct CoProcessMessage* outputObject = malloc(sizeof *outputObject);

	printf("TestDispatchHook: %p\n", object);

	outputObject->p_data = object->p_data;
	outputObject->length = object->length;

	applyTestHooks(outputObject);

  return outputObject;
};

*/
import "C"

import (
	"strings"
	"unsafe"

	"github.com/TykTechnologies/tyk/coprocess"
	"github.com/golang/protobuf/proto"
)

var CoProcessReload = make(chan bool)

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
	CoProcessReload <- true
	return
}

/* General test helpers */

func NewCoProcessDispatcher() (dispatcher *TestDispatcher, err error) {
	d := &TestDispatcher{}
	return d, nil
}

func (d *TestDispatcher) ToCoProcessMessage(object *coprocess.Object) unsafe.Pointer {
	objectMsg, _ := proto.Marshal(object)

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

func TestTykStoreData(key string, value string, ttl int) {
	Ckey := C.CString(key)
	Cvalue := C.CString(value)
	Cttl := C.int(ttl)
	TykStoreData(Ckey, Cvalue, Cttl)
}

func TestTykGetData(key string) string {
	Ckey := C.CString(key)
	Cvalue := TykGetData(Ckey)
	return C.GoString(Cvalue)
}

/* Events */

func TestTykTriggerEvent(eventName string, eventPayload string) {
	CeventName := C.CString(eventName)
	CeventPayload := C.CString(eventPayload)
	TykTriggerEvent(CeventName, CeventPayload)
}

/* Middleware */

//export applyTestHooks
func applyTestHooks(objectPtr unsafe.Pointer) {
	var objectStruct *C.struct_CoProcessMessage
	objectStruct = (*C.struct_CoProcessMessage)(objectPtr)

	objectBytes := C.GoBytes(objectStruct.p_data, objectStruct.length)

	object := &coprocess.Object{}
	proto.Unmarshal(objectBytes, object)

	if strings.Index(object.HookName, "hook_test") != 0 {
		return
	}

	switch object.HookName {
	case "hook_test_object_postprocess":
		object.Request.SetHeaders = map[string]string{
			"test": "value",
		}
		object.Request.DeleteHeaders = []string{"Deletethisheader"}

		object.Request.AddParams = map[string]string{
			"customparam": "customvalue",
		}
		object.Request.DeleteParams = []string{"remove"}
	}

	newObject, _ := proto.Marshal(object)

	newObjectBytes := C.CBytes(newObject)
	newObjectLength := C.int(len(newObject))

	objectStruct.p_data = unsafe.Pointer(newObjectBytes)
	objectStruct.length = newObjectLength
}
