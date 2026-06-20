package accesslog_test

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/httputil/accesslog"
)

// Verifies: SYS-REQ-082, SW-REQ-046
// SW-REQ-046:nominal:nominal
// SW-REQ-046:boundary:nominal
// SW-REQ-046:boundary:boundary
// SW-REQ-046:determinism:nominal
func TestFilter(t *testing.T) {
	tests := []struct {
		name          string
		in            logrus.Fields
		allowedFields []string
		want          logrus.Fields
		wantSameMap   bool
	}{
		{
			name: "retains only configured fields",
			in: logrus.Fields{
				"a": "b",
				"b": "c",
				"c": "d",
			},
			allowedFields: []string{"a", "c"},
			want: logrus.Fields{
				"a": "b",
				"c": "d",
			},
		},
		{
			name: "empty allowed fields returns input map",
			in: logrus.Fields{
				"a": "b",
				"b": "c",
			},
			allowedFields: nil,
			want: logrus.Fields{
				"a": "b",
				"b": "c",
			},
			wantSameMap: true,
		},
		{
			name: "prefix is retained by default when filtering",
			in: logrus.Fields{
				"prefix": "gateway",
				"a":      "b",
				"b":      "c",
			},
			allowedFields: []string{"a"},
			want: logrus.Fields{
				"prefix": "gateway",
				"a":      "b",
			},
		},
		{
			name: "matching is case sensitive",
			in: logrus.Fields{
				"Path": "/upper",
				"path": "/lower",
			},
			allowedFields: []string{"path"},
			want: logrus.Fields{
				"path": "/lower",
			},
		},
		{
			name: "absent allowed fields are omitted",
			in: logrus.Fields{
				"a": "b",
			},
			allowedFields: []string{"missing"},
			want:          logrus.Fields{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := accesslog.Filter(tt.in, tt.allowedFields)
			require.Equal(t, tt.want, got)
			if tt.wantSameMap {
				got["new"] = "value"
				require.Equal(t, "value", tt.in["new"])
			}
		})
	}
}
