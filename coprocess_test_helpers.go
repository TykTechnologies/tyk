// +build coprocess
// +build !python
// +build !lua
// +build !grpc

package main

/*
#include <stdio.h>
#include <stdlib.h>

#include "coprocess/api.h"

void applyTestHooks();

static int TestMessageLength(struct CoProcessMessage* object) {
	return object->length;
}

static struct CoProcessMessage* TestDispatchHook(struct CoProcessMessage* object) {
	struct CoProcessMessage* outputObject = malloc(sizeof *outputObject);

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

	"github.com/golang/protobuf/proto"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/coprocess"
)

var CoProcessReload = make(chan bool)
var CoProcessDispatchEvent = make(chan []byte)

type TestDispatcher struct {
	coprocess.Dispatcher
	reloaded bool
}

/* Basic CoProcessDispatcher functions */

func (d *TestDispatcher) Dispatch(objectPtr unsafe.Pointer) unsafe.Pointer {
	object := (*C.struct_CoProcessMessage)(objectPtr)
	newObjectPtr := C.TestDispatchHook(object)
	return unsafe.Pointer(newObjectPtr)
}

func (d *TestDispatcher) DispatchEvent(eventJSON []byte) {
	CoProcessDispatchEvent <- eventJSON
}

func (d *TestDispatcher) Reload() {
	d.reloaded = true
}

/* General test helpers */

func NewCoProcessDispatcher() (dispatcher *TestDispatcher, err error) {
	d := &TestDispatcher{}
	GlobalDispatcher = d
	EnableCoProcess = true
	return d, nil
}

func (d *TestDispatcher) ToCoProcessMessage(object *coprocess.Object) unsafe.Pointer {
	objectMsg, _ := proto.Marshal(object)

	objectMsgStr := string(objectMsg)
	CObjectStr := C.CString(objectMsgStr)

	messagePtr := (*C.struct_CoProcessMessage)(C.malloc(C.size_t(unsafe.Sizeof(C.struct_CoProcessMessage{}))))
	messagePtr.p_data = unsafe.Pointer(CObjectStr)
	messagePtr.length = C.int(len(objectMsg))

	return unsafe.Pointer(messagePtr)
}

func (d *TestDispatcher) ToCoProcessObject(messagePtr unsafe.Pointer) *coprocess.Object {
	message := (*C.struct_CoProcessMessage)(messagePtr)
	object := &coprocess.Object{}

	objectBytes := C.GoBytes(message.p_data, message.length)
	proto.Unmarshal(objectBytes, object)
	return object
}

func (d *TestDispatcher) TestMessageLength(messagePtr unsafe.Pointer) int {
	message := (*C.struct_CoProcessMessage)(messagePtr)
	return int(C.TestMessageLength(message))
}

func (d *TestDispatcher) HandleMiddlewareCache(b *apidef.BundleManifest, basePath string) {}

func TestTykStoreData(key, value string, ttl int) {
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

func TestTykTriggerEvent(eventName, eventPayload string) {
	CeventName := C.CString(eventName)
	CeventPayload := C.CString(eventPayload)
	TykTriggerEvent(CeventName, CeventPayload)
}

/* Middleware */

//export applyTestHooks
func applyTestHooks(objectPtr unsafe.Pointer) {
	objectStruct := (*C.struct_CoProcessMessage)(objectPtr)
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
	case "hook_test_bad_auth":
		object.Request.ReturnOverrides = &coprocess.ReturnOverrides{
			ResponseCode:  403,
			ResponseError: "Key not authorised",
		}
	case "hook_test_return_overrides":
		object.Request.ReturnOverrides = &coprocess.ReturnOverrides{
			Headers: map[string]string{
				"header": "value",
			},
			ResponseCode:  200,
			ResponseError: "body",
		}
	case "hook_test_return_overrides_error":
		object.Request.ReturnOverrides = &coprocess.ReturnOverrides{
			ResponseCode:  401,
			ResponseError: "custom error message",
		}
	case "hook_test_bad_auth_using_id_extractor":
	case "hook_test_bad_auth_cp_error":
	case "hook_test_successful_auth":
	case "hook_test_successful_auth_using_id_extractor":
	}

	newObject, _ := proto.Marshal(object)
	newObjectStr := string(newObject)

	newObjectBytes := C.CString(newObjectStr)
	newObjectLength := C.int(len(newObject))

	objectStruct.p_data = unsafe.Pointer(newObjectBytes)
	objectStruct.length = newObjectLength
}
