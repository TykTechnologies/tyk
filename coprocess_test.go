// +build coprocess

package main

import(
  "testing"
  "unsafe"

  "github.com/golang/protobuf/proto"

  // "github.com/TykTechnologies/tykcommon"
  "github.com/TykTechnologies/tyk/coprocess"
  "github.com/TykTechnologies/tyk/coprocess/test"
)

const(
  baseMiddlewarePath = "middleware/python"
)


var TestDispatcher, _ = coprocess_test.NewDispatcher()

/* Dispatcher logic */

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
  messagePtr = coprocess_test.ToCoProcessMessage(object)

  var length int
  length = coprocess_test.TestMessageLength(messagePtr)

  if len(data) != length {
    err := "The length of the serialized object doesn't match."
    t.Fatal(err)
  }
}
