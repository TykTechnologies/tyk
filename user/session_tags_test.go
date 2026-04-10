package user

import (
	"testing"
)

func TestSessionState_TagsFromMetadata(t *testing.T) {
	tests := []struct {
		name              string
		session           *SessionState
		data              map[string]interface{}
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
				"tyk_developer_id": "456",
				"policies":         []interface{}{"[]"},
				"tags":             []interface{}{"pteam-456", "porg-456"},
			},
			wantUpdateSession: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotUpdateSession := tt.session.TagsFromMetadata(tt.data); gotUpdateSession != tt.wantUpdateSession {
				t.Errorf("SessionState.TagsFromMetadata() = %v, want %v", gotUpdateSession, tt.wantUpdateSession)
			}
		})
	}
}
