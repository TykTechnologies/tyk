package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJSVMEventHandler_Init(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	spec := BuildAPI()[0]

	t.Run("init jsvm event handler based on enable/disable flag", func(t *testing.T) {
		setupHandlerAndMeta := func(handlerEnabled bool) (*JSVMEventHandler, map[string]any) {
			eventHandler := JSVMEventHandler{
				Gw:   ts.Gw,
				Spec: spec,
			}

			meta := map[string]any{
				"disabled": !handlerEnabled,
				"id":       "1234",
				"name":     "myMethod",
				"path":     "my_script.js",
			}

			return &eventHandler, meta
		}

		t.Run("on enabled", func(t *testing.T) {
			jsvmHandler, meta := setupHandlerAndMeta(true)
			err := jsvmHandler.Init(meta)
			assert.NoError(t, err)
			assert.Equal(t, jsvmHandler.conf.MethodName, meta["name"])
		})

		t.Run("on disabled", func(t *testing.T) {
			jsvmHandler, meta := setupHandlerAndMeta(false)
			err := jsvmHandler.Init(meta)
			assert.ErrorIs(t, err, ErrEventHandlerDisabled)
		})
	})
}
