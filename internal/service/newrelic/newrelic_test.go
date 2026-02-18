package newrelic

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/stretchr/testify/assert"
)

func TestRenameRelicTransactionMiddleware(t *testing.T) {
	app, err := newrelic.NewApplication(newrelic.ConfigEnabled(false))
	assert.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	targetPath := "/my/path"

	t.Run("renames transaction with method and path", func(t *testing.T) {
		method := http.MethodGet

		req := httptest.NewRequest(method, targetPath, nil)
		res := httptest.NewRecorder()

		txn := app.StartTransaction("renameTxnGet")
		defer txn.End()

		ctx := newrelic.NewContext(req.Context(), txn)
		req = req.WithContext(ctx)

		middleware := renameRelicTransactionMiddleware(handler)
		middleware.ServeHTTP(res, req)

		assert.Equal(t, targetPath, txn.Name())
	})

	t.Run("does not panic if no transaction in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, targetPath, nil)
		res := httptest.NewRecorder()

		txnName := "customName"
		txn := app.StartTransaction(txnName)
		defer txn.End()

		var handlerCalled bool
		handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})
		middleware := renameRelicTransactionMiddleware(handler)

		assert.NotPanics(t, func() {
			middleware.ServeHTTP(res, req)
		})
		assert.True(t, handlerCalled)
		assert.Equal(t, txnName, txn.Name())
	})

	t.Run("handles different methods", func(t *testing.T) {
		method := http.MethodPost

		req := httptest.NewRequest(method, targetPath, nil)
		res := httptest.NewRecorder()

		txn := app.StartTransaction("renameTxnPost")
		defer txn.End()

		ctx := newrelic.NewContext(req.Context(), txn)
		req = req.WithContext(ctx)

		middleware := renameRelicTransactionMiddleware(handler)
		middleware.ServeHTTP(res, req)

		assert.Equal(t, targetPath, txn.Name())
	})
}
