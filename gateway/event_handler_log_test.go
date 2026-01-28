package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogMessageEventHandler_Init(t *testing.T) {
	ts := StartTest(nil)
	t.Cleanup(ts.Close)

	t.Run("init log event handler based on enable/disable flag", func(t *testing.T) {
		setupHandlerAndMeta := func(handlerEnabled bool) (*LogMessageEventHandler, map[string]any) {
			eventHandler := LogMessageEventHandler{
				Gw: ts.Gw,
			}

			meta := map[string]any{
				"disabled": !handlerEnabled,
				"prefix":   "AuthFailureEvent",
			}

			return &eventHandler, meta
		}

		t.Run("on enabled", func(t *testing.T) {
			logHandler, meta := setupHandlerAndMeta(true)
			err := logHandler.Init(meta)
			assert.NoError(t, err)
			assert.Equal(t, logHandler.conf.Prefix, meta["prefix"])
		})

		t.Run("on disabled", func(t *testing.T) {
			logHandler, meta := setupHandlerAndMeta(false)
			err := logHandler.Init(meta)
			assert.ErrorIs(t, err, ErrEventHandlerDisabled)
		})
	})
}
