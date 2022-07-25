package gateway

import (
	"testing"
)

func TestCgoTykStoreGetData(t *testing.T) {
	ts := StartTest(nil)
	defer ts.Close()
	cgoTykStoreData("testkey", "testvalue", 5)
	retVal := cgoTykGetData("testkey")
	if retVal != "testvalue" {
		t.Fatal("couldn't get Redis key")
	}
}
