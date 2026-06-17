package apidef

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	tyktime "github.com/TykTechnologies/tyk/internal/time"
)

func TestAPIDefinition_FillHardTimeoutDeprecatedFields(t *testing.T) {
	makeAPI := func(metas ...HardTimeoutMeta) *APIDefinition {
		return &APIDefinition{
			VersionData: VersionData{
				Versions: map[string]VersionInfo{
					"Default": {
						ExtendedPaths: ExtendedPathsSet{HardTimeouts: metas},
					},
				},
			},
		}
	}

	get := func(a *APIDefinition) HardTimeoutMeta {
		return a.VersionData.Versions["Default"].ExtendedPaths.HardTimeouts[0]
	}

	t.Run("rounds duration up and overwrites legacy timeout", func(t *testing.T) {
		api := makeAPI(HardTimeoutMeta{
			Path:            "/get",
			Method:          http.MethodGet,
			TimeOut:         5,
			TimeoutDuration: tyktime.ReadableDuration(1200 * time.Millisecond),
		})
		api.FillHardTimeoutDeprecatedFields()
		assert.Equal(t, 2, get(api).TimeOut)
		assert.Equal(t, tyktime.ReadableDuration(1200*time.Millisecond), get(api).TimeoutDuration)
	})

	t.Run("sub-second duration rounds up to one second", func(t *testing.T) {
		api := makeAPI(HardTimeoutMeta{
			Path:            "/get",
			Method:          http.MethodGet,
			TimeoutDuration: tyktime.ReadableDuration(500 * time.Millisecond),
		})
		api.FillHardTimeoutDeprecatedFields()
		assert.Equal(t, 1, get(api).TimeOut)
	})

	t.Run("no duration leaves legacy timeout untouched", func(t *testing.T) {
		api := makeAPI(HardTimeoutMeta{
			Path:    "/get",
			Method:  http.MethodGet,
			TimeOut: 3,
		})
		api.FillHardTimeoutDeprecatedFields()
		assert.Equal(t, 3, get(api).TimeOut)
		assert.Equal(t, tyktime.ReadableDuration(0), get(api).TimeoutDuration)
	})

	t.Run("exact whole-second duration is not rounded further", func(t *testing.T) {
		api := makeAPI(HardTimeoutMeta{
			Path:            "/get",
			Method:          http.MethodGet,
			TimeOut:         9,
			TimeoutDuration: tyktime.ReadableDuration(2 * time.Second),
		})
		api.FillHardTimeoutDeprecatedFields()
		assert.Equal(t, 2, get(api).TimeOut, "exact 2s must stay 2, not round to 3")
	})

	t.Run("applies per entry across multiple versions, leaving no-duration entries untouched", func(t *testing.T) {
		api := &APIDefinition{
			VersionData: VersionData{
				Versions: map[string]VersionInfo{
					"v1": {
						ExtendedPaths: ExtendedPathsSet{HardTimeouts: []HardTimeoutMeta{
							{Path: "/a", Method: http.MethodGet, TimeoutDuration: tyktime.ReadableDuration(1200 * time.Millisecond)},
							{Path: "/b", Method: http.MethodGet, TimeOut: 7},
						}},
					},
					"v2": {
						ExtendedPaths: ExtendedPathsSet{HardTimeouts: []HardTimeoutMeta{
							{Path: "/c", Method: http.MethodGet, TimeoutDuration: tyktime.ReadableDuration(500 * time.Millisecond)},
						}},
					},
				},
			},
		}

		api.FillHardTimeoutDeprecatedFields()

		v1 := api.VersionData.Versions["v1"].ExtendedPaths.HardTimeouts
		assert.Equal(t, 2, v1[0].TimeOut, "v1 /a 1.2s rounds up to 2 (mutation must persist through the map)")
		assert.Equal(t, 7, v1[1].TimeOut, "v1 /b without duration must be left untouched")
		assert.Equal(t, 1, api.VersionData.Versions["v2"].ExtendedPaths.HardTimeouts[0].TimeOut, "v2 /c 500ms rounds up to 1")
	})
}
