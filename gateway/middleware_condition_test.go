package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/condition"
)

func TestBaseMiddleware_ConditionCheck(t *testing.T) {
	t.Run("no condition - middleware always runs", func(t *testing.T) {
		bm := &BaseMiddleware{}
		assert.Nil(t, bm.conditionFunc)
	})

	t.Run("condition true - middleware runs", func(t *testing.T) {
		fn, err := condition.Compile(`request.method == "GET"`)
		assert.NoError(t, err)

		r := httptest.NewRequest("GET", "/", nil)
		assert.True(t, safeEvalCondition(fn, r, nil))
	})

	t.Run("condition false - middleware skipped", func(t *testing.T) {
		fn, err := condition.Compile(`request.method == "POST"`)
		assert.NoError(t, err)

		r := httptest.NewRequest("GET", "/", nil)
		assert.False(t, safeEvalCondition(fn, r, nil))
	})

	t.Run("condition panics - middleware executes (fail-closed)", func(t *testing.T) {
		panicFn := condition.ConditionFunc(func(r *http.Request, m map[string]interface{}) bool {
			panic("test panic")
		})

		r := httptest.NewRequest("GET", "/", nil)
		// safeEvalCondition should recover and return true (fail-closed)
		assert.True(t, safeEvalCondition(panicFn, r, nil))
	})
}

func TestBaseMiddleware_CompileCondition(t *testing.T) {
	t.Run("empty condition - no func set", func(t *testing.T) {
		bm := &BaseMiddleware{}
		err := bm.CompileCondition()
		assert.NoError(t, err)
		assert.Nil(t, bm.conditionFunc)
	})

	t.Run("valid condition - func set", func(t *testing.T) {
		bm := &BaseMiddleware{Condition: `request.method == "GET"`}
		err := bm.CompileCondition()
		assert.NoError(t, err)
		assert.NotNil(t, bm.conditionFunc)
	})

	t.Run("invalid condition - error returned", func(t *testing.T) {
		bm := &BaseMiddleware{Condition: `invalid ==`}
		err := bm.CompileCondition()
		assert.Error(t, err)
	})
}

func TestBaseTykResponseHandler_ConditionCheck(t *testing.T) {
	t.Run("no condition - handler runs", func(t *testing.T) {
		bh := &BaseTykResponseHandler{}
		assert.Nil(t, bh.conditionFunc)
	})

	t.Run("condition true - handler runs", func(t *testing.T) {
		fn, err := condition.Compile(`request.method == "GET"`)
		assert.NoError(t, err)

		r := httptest.NewRequest("GET", "/", nil)
		assert.True(t, safeEvalCondition(fn, r, nil))
	})

	t.Run("condition false - handler skipped", func(t *testing.T) {
		fn, err := condition.Compile(`request.method == "POST"`)
		assert.NoError(t, err)

		r := httptest.NewRequest("GET", "/", nil)
		assert.False(t, safeEvalCondition(fn, r, nil))
	})

	t.Run("condition panics - handler runs (fail-closed)", func(t *testing.T) {
		panicFn := condition.ConditionFunc(func(r *http.Request, m map[string]interface{}) bool {
			panic("test panic")
		})

		r := httptest.NewRequest("GET", "/", nil)
		assert.True(t, safeEvalCondition(panicFn, r, nil))
	})
}

func TestBaseTykResponseHandler_CompileCondition(t *testing.T) {
	t.Run("empty condition", func(t *testing.T) {
		bh := &BaseTykResponseHandler{}
		err := bh.CompileCondition()
		assert.NoError(t, err)
		assert.Nil(t, bh.conditionFunc)
	})

	t.Run("valid condition", func(t *testing.T) {
		bh := &BaseTykResponseHandler{Condition: `request.path contains "/api"`}
		err := bh.CompileCondition()
		assert.NoError(t, err)
		assert.NotNil(t, bh.conditionFunc)
	})
}
