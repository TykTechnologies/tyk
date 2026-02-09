package gateway

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ctxGetOrCreateData(t *testing.T) {
	t.Run("returns data if already exists", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), "GET", "/", nil)
		require.NoError(t, err)

		ctxSetData(req, CtxData{"hello": "world0"})

		assert.Equal(t, CtxData{"hello": "world0"}, ctxGetOrCreateData(req))
	})

	t.Run("create new data if not exists", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), "GET", "/", nil)
		require.NoError(t, err)

		data1 := ctxGetOrCreateData(req)
		data1["hello"] = "world1"

		data2 := ctxGetOrCreateData(req)

		assert.Equal(t, data1, data2)
	})
}
