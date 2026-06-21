package user

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verifies: STK-REQ-069, SYS-REQ-157, SW-REQ-144
// SW-REQ-144:nominal:nominal
// SW-REQ-144:boundary:nominal
// SW-REQ-144:boundary:boundary
// SW-REQ-144:encoding_safety:nominal
func TestSessionState_TagsFromMetadata(t *testing.T) {
	tests := []struct {
		name              string
		session           *SessionState
		data              map[string]interface{}
		wantMetadata      map[string]interface{}
		wantTags          []string
		wantUpdateSession bool
	}{
		{
			name: "all-values",
			session: &SessionState{
				MetaData: map[string]interface{}{
					"tyk_developer_id": "123",
					"policies":         []interface{}{"[]"},
					"tags":             []interface{}{"pteam-123", "porg-123"},
				},
			},
			data: map[string]interface{}{
				"tyk_developer_id":   "456",
				"policies":           []interface{}{"[]"},
				"tags":               []interface{}{"pteam-456", "porg-456"},
				"rate_limit_pattern": "client-ip",
			},
			wantMetadata: map[string]interface{}{
				"tyk_developer_id":   "456",
				"policies":           []interface{}{"[]"},
				"rate_limit_pattern": "client-ip",
				"tags":               []interface{}{"pteam-123", "porg-123"},
			},
			wantTags:          []string{"pteam-456", "porg-456"},
			wantUpdateSession: true,
		},
		{
			name: "no-supported-values",
			session: &SessionState{
				MetaData: map[string]interface{}{},
			},
			data:              map[string]interface{}{"tags": "not-a-list"},
			wantMetadata:      map[string]interface{}{},
			wantUpdateSession: false,
		},
		{
			name: "ignores-non-string-tags",
			session: &SessionState{
				MetaData: map[string]interface{}{},
			},
			data: map[string]interface{}{
				"tags": []interface{}{"pteam-456", 123, "porg-456"},
			},
			wantMetadata:      map[string]interface{}{},
			wantTags:          []string{"pteam-456", "porg-456"},
			wantUpdateSession: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotUpdateSession := tt.session.TagsFromMetadata(tt.data); gotUpdateSession != tt.wantUpdateSession {
				t.Errorf("SessionState.TagsFromMetadata() = %v, want %v", gotUpdateSession, tt.wantUpdateSession)
			}
			assert.Equal(t, tt.wantMetadata, tt.session.MetaData)
			assert.Equal(t, tt.wantTags, tt.session.Tags)
		})
	}
}
