package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/config"
)

func TestCollectAllMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("authCheck only no slices", func(t *testing.T) {
		t.Parallel()
		authCheck := apidef.MiddlewareDefinition{Name: "myAuth", Path: "/auth.js"}
		result := collectAllMiddleware(authCheck)

		require.Len(t, result, 1)
		assert.Equal(t, "myAuth", result[0].Name)
		assert.Equal(t, "/auth.js", result[0].Path)
	})

	t.Run("authCheck plus multiple slices", func(t *testing.T) {
		t.Parallel()
		authCheck := apidef.MiddlewareDefinition{Name: "auth"}
		pre := []apidef.MiddlewareDefinition{
			{Name: "pre1"},
			{Name: "pre2"},
		}
		post := []apidef.MiddlewareDefinition{
			{Name: "post1"},
		}
		response := []apidef.MiddlewareDefinition{
			{Name: "resp1"},
			{Name: "resp2"},
			{Name: "resp3"},
		}

		result := collectAllMiddleware(authCheck, pre, post, response)

		require.Len(t, result, 7)
		assert.Equal(t, "auth", result[0].Name)
		assert.Equal(t, "pre1", result[1].Name)
		assert.Equal(t, "pre2", result[2].Name)
		assert.Equal(t, "post1", result[3].Name)
		assert.Equal(t, "resp1", result[4].Name)
		assert.Equal(t, "resp2", result[5].Name)
		assert.Equal(t, "resp3", result[6].Name)
	})

	t.Run("empty authCheck and empty slices returns one zero value", func(t *testing.T) {
		t.Parallel()
		var authCheck apidef.MiddlewareDefinition
		result := collectAllMiddleware(authCheck, []apidef.MiddlewareDefinition{}, []apidef.MiddlewareDefinition{})

		require.Len(t, result, 1)
		assert.Equal(t, apidef.MiddlewareDefinition{}, result[0])
	})

	t.Run("skips empty slices includes non-empty", func(t *testing.T) {
		t.Parallel()
		authCheck := apidef.MiddlewareDefinition{Name: "auth"}
		emptySlice := []apidef.MiddlewareDefinition{}
		nonEmpty := []apidef.MiddlewareDefinition{{Name: "mw1"}}
		anotherEmpty := []apidef.MiddlewareDefinition{}

		result := collectAllMiddleware(authCheck, emptySlice, nonEmpty, anotherEmpty)

		require.Len(t, result, 2)
		assert.Equal(t, "auth", result[0].Name)
		assert.Equal(t, "mw1", result[1].Name)
	})
}

func TestLoadCustomMiddleware(t *testing.T) {
	t.Parallel()

	// newGateway creates a minimal Gateway with config loaded so that
	// loadCustomMiddleware can call gw.GetConfig() without panicking.
	// MiddlewarePath is set to a non-existent directory so the folder-based
	// glob scan finds nothing and doesn't interfere with our assertions.
	newGateway := func() *Gateway {
		gw := &Gateway{}
		gw.SetConfig(config.Config{
			MiddlewarePath: "/tmp/nonexistent-tyk-mw-test-path",
		})
		return gw
	}

	newSpec := func(cm apidef.MiddlewareSection) *APISpec {
		return &APISpec{
			APIDefinition: &apidef.APIDefinition{
				CustomMiddleware: cm,
			},
		}
	}

	t.Run("pre middleware with Code set does not add Path to mwPaths", func(t *testing.T) {
		t.Parallel()
		gw := newGateway()
		spec := newSpec(apidef.MiddlewareSection{
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "inlinePre",
					Path: "/should/not/appear.js",
					Code: "dmFyIHg9MTsK",
				},
			},
		})

		mwPaths, _, mwPreFuncs, _, _, _, _ := gw.loadCustomMiddleware(spec)

		assert.Empty(t, mwPaths, "mwPaths should be empty when Code is set")
		require.Len(t, mwPreFuncs, 1)
		assert.Equal(t, "inlinePre", mwPreFuncs[0].Name)
		assert.Equal(t, "dmFyIHg9MTsK", mwPreFuncs[0].Code)
	})

	t.Run("pre middleware with Code empty adds Path to mwPaths", func(t *testing.T) {
		t.Parallel()
		gw := newGateway()
		spec := newSpec(apidef.MiddlewareSection{
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "filePre",
					Path: "/path/to/file.js",
					Code: "",
				},
			},
		})

		mwPaths, _, mwPreFuncs, _, _, _, _ := gw.loadCustomMiddleware(spec)

		require.Len(t, mwPaths, 1)
		assert.Equal(t, "/path/to/file.js", mwPaths[0])
		require.Len(t, mwPreFuncs, 1)
		assert.Equal(t, "filePre", mwPreFuncs[0].Name)
	})

	t.Run("authCheck with Code set does not add Path to mwPaths", func(t *testing.T) {
		t.Parallel()
		gw := newGateway()
		spec := newSpec(apidef.MiddlewareSection{
			AuthCheck: apidef.MiddlewareDefinition{
				Name: "inlineAuth",
				Path: "/auth/file.js",
				Code: "dmFyIGF1dGg9MTsK",
			},
		})

		mwPaths, mwAuthCheck, _, _, _, _, _ := gw.loadCustomMiddleware(spec)

		assert.Empty(t, mwPaths, "mwPaths should be empty when AuthCheck has Code set")
		assert.Equal(t, "inlineAuth", mwAuthCheck.Name)
		assert.Equal(t, "dmFyIGF1dGg9MTsK", mwAuthCheck.Code)
	})

	t.Run("disabled middleware is skipped entirely", func(t *testing.T) {
		t.Parallel()
		gw := newGateway()
		spec := newSpec(apidef.MiddlewareSection{
			Pre: []apidef.MiddlewareDefinition{
				{
					Disabled: true,
					Name:     "disabledPre",
					Path:     "/disabled.js",
				},
			},
			Post: []apidef.MiddlewareDefinition{
				{
					Disabled: true,
					Name:     "disabledPost",
					Path:     "/disabled-post.js",
					Code:     "dmFyIHg9MTsK",
				},
			},
		})

		mwPaths, _, mwPreFuncs, mwPostFuncs, _, _, _ := gw.loadCustomMiddleware(spec)

		assert.Empty(t, mwPaths, "disabled middleware should not add paths")
		assert.Empty(t, mwPreFuncs, "disabled pre middleware should not be in func slice")
		assert.Empty(t, mwPostFuncs, "disabled post middleware should not be in func slice")
	})

	t.Run("mix of Code-based and Path-based middleware", func(t *testing.T) {
		t.Parallel()
		gw := newGateway()
		spec := newSpec(apidef.MiddlewareSection{
			Pre: []apidef.MiddlewareDefinition{
				{
					Name: "inlinePre",
					Code: "dmFyIHByZTE9MTsK",
				},
				{
					Name: "filePre",
					Path: "/pre/file.js",
				},
			},
			Post: []apidef.MiddlewareDefinition{
				{
					Name: "filePost",
					Path: "/post/file.js",
				},
				{
					Name: "inlinePost",
					Code: "dmFyIHBvc3QxPTE7Cg==",
				},
			},
			AuthCheck: apidef.MiddlewareDefinition{
				Name: "inlineAuth",
				Code: "dmFyIGF1dGg9MTsK",
				Path: "/auth/should-not-appear.js",
			},
		})

		mwPaths, mwAuthCheck, mwPreFuncs, mwPostFuncs, _, _, _ := gw.loadCustomMiddleware(spec)

		// Only Path-based (Code=="") entries should appear in mwPaths
		assert.Equal(t, []string{"/pre/file.js", "/post/file.js"}, mwPaths)

		// All non-disabled middleware should be in func slices
		require.Len(t, mwPreFuncs, 2)
		assert.Equal(t, "inlinePre", mwPreFuncs[0].Name)
		assert.Equal(t, "filePre", mwPreFuncs[1].Name)

		require.Len(t, mwPostFuncs, 2)
		assert.Equal(t, "filePost", mwPostFuncs[0].Name)
		assert.Equal(t, "inlinePost", mwPostFuncs[1].Name)

		// AuthCheck with Code set should not have added its Path
		assert.Equal(t, "inlineAuth", mwAuthCheck.Name)
		assert.Equal(t, "dmFyIGF1dGg9MTsK", mwAuthCheck.Code)
	})

	t.Run("driver is passed through from spec", func(t *testing.T) {
		t.Parallel()
		gw := newGateway()
		spec := newSpec(apidef.MiddlewareSection{
			Driver: apidef.JavaScriptDriver,
		})

		_, _, _, _, _, _, mwDriver := gw.loadCustomMiddleware(spec)

		assert.Equal(t, apidef.JavaScriptDriver, mwDriver)
	})
}
