package coprocess_test

/*
#include <stdio.h>

#include "../sds/sds.h"

#include "../api.h"

static struct CoProcessMessage* TestDispatchHook(struct CoProcessMessage* object) {
  return object;
};

*/
import "C"

type CoProcessDispatcher interface {
	Dispatch(*C.struct_CoProcessMessage) *C.struct_CoProcessMessage
	DispatchEvent([]byte)
	Reload()
}

type TestDispatcher struct {
	CoProcessDispatcher
}

func (d *TestDispatcher) Dispatch(objectPtr *C.struct_CoProcessMessage) *C.struct_CoProcessMessage {
	var newObjectPtr *C.struct_CoProcessMessage
	newObjectPtr = C.TestDispatchHook(objectPtr)

	return newObjectPtr
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

func NewTestDispatcher() (dispatcher CoProcessDispatcher, err error) {
	d := &TestDispatcher{}
	return d, nil
}
