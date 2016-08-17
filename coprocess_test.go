// +build coprocess

package main

import(
  "testing"
  "unsafe"

  // "github.com/TykTechnologies/tykcommon"
  "github.com/TykTechnologies/tyk/coprocess"
  "github.com/TykTechnologies/tyk/coprocess/test"
)

const(
  baseMiddlewarePath = "middleware/python"
)


var TestDispatcher, _ = coprocess_test.NewDispatcher()

func TestCoProcessDispatch(t *testing.T) {
  var object, newObject *coprocess.Object
  var messagePtr, newMessagePtr unsafe.Pointer

  object = &coprocess.Object{
    HookType: coprocess.HookType_Pre,
    HookName: "test_hook",
  }

  messagePtr = coprocess_test.ToCoProcessMessage(object)
  newMessagePtr = TestDispatcher.Dispatch(messagePtr)

  newObject = coprocess_test.ToCoProcessObject(newMessagePtr)

  t.Log(newObject)

}
