package gateway

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/apidef"
)

func TestCoprocessAPIs(t *testing.T) {
	k := "keyName"
	v := "valueOf"

	key := cgoCString(k)
	val := cgoCString(v)
	ttl := cgoCint(60)

	TykStoreData(key, val, ttl)

	result := TykGetData(key)

	assert.True(t, cgoGoString(result) == v)
}

func TestCoprocessLog(t *testing.T) {
	levels := []string{"debug", "error", "warning", "info"}
	for idx, level := range levels {
		CoProcessLog(cgoCString(fmt.Sprintf("test logging message %d", idx)), cgoCString(level))
	}
	assert.True(t, true)
}

func TestCoprocessSystemEvent(t *testing.T) {
	name := cgoCString("test-event")
	payload := cgoCString("test-payload")

	invoked := false
	GatewayFireSystemEvent = func(name apidef.TykEvent, meta interface{}) {
		invoked = true

		metaVal, ok := meta.(EventMetaDefault)

		assert.True(t, ok)
		assert.Equal(t, "test-event", string(name))
		assert.Equal(t, "test-payload", metaVal.Message)
	}

	TykTriggerEvent(name, payload)

	assert.True(t, invoked, "should invoke global fire event hook")
}
