// +build coprocess
// +build !python

package main

import(
  "testing"
  "unsafe"

  "github.com/golang/protobuf/proto"

  // "github.com/TykTechnologies/tykcommon"
  "github.com/TykTechnologies/tyk/coprocess"
)

const(
  baseMiddlewarePath = "middleware/python"
)

var CoProcessName = "test"
var thisTestDispatcher, _ = NewCoProcessDispatcher()

/* Dispatcher logic */

func TestCoProcessDispatch(t *testing.T) {
  var object, newObject *coprocess.Object
  var messagePtr, newMessagePtr unsafe.Pointer

  object = &coprocess.Object{
    HookType: coprocess.HookType_Pre,
    HookName: "test_hook",
  }

  messagePtr = thisTestDispatcher.ToCoProcessMessage(object)
  newMessagePtr = thisTestDispatcher.Dispatch(messagePtr)

  newObject = thisTestDispatcher.ToCoProcessObject(newMessagePtr)

  t.Log(newObject)

}

/* Serialization, CP Objects */

func TestCoProcessSerialization(t *testing.T) {
  var object *coprocess.Object

  object = &coprocess.Object{
    HookType: coprocess.HookType_Pre,
    HookName: "test_hook",
  }

  data, err := proto.Marshal(object)

  if err != nil {
    t.Fatal(err)
  }

  var messagePtr unsafe.Pointer
  messagePtr = thisTestDispatcher.ToCoProcessMessage(object)

  var length int
  length = thisTestDispatcher.TestMessageLength(messagePtr)

  if len(data) != length {
    err := "The length of the serialized object doesn't match."
    t.Fatal(err)
  }
}
