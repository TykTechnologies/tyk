//go:build !goplugin
// +build !goplugin

package goplugin

import (
	"fmt"

	"github.com/TykTechnologies/tyk-pump/analytics"
)

// SW-REQ-125
func GetAnalyticsHandler(path string, symbol string) (func(record *analytics.AnalyticsRecord), error) {
	return nil, fmt.Errorf("goplugin.GetAnalyticsHandler is disabled, please disable build flag 'nogoplugin'")

}
