package user

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionState_CustomPolicies(t *testing.T) {
	tests := []struct {
		name    string
		session *SessionState
		want    map[string]Policy
		wantErr bool
	}{
		{
			name:    "empty-session",
			session: &SessionState{},
			want:    nil,
			wantErr: true,
		},

		{
			name: "policies-nil",
			session: &SessionState{
				MetaData: map[string]interface{}{"policies": nil},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "policies-empty",
			session: &SessionState{
				MetaData: map[string]interface{}{"policies": ""},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "policies-invalid-json",
			session: &SessionState{
				MetaData: map[string]interface{}{"policies": []interface{}{}},
			},
			want:    map[string]Policy{},
			wantErr: false,
		},
		{
			name: "policies-invalid-object",
			session: &SessionState{
				MetaData: map[string]interface{}{"policies": []interface{}{TestSessionState_SetCustomPolicies}},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "policies-valid-json",
			session: &SessionState{
				MetaData: map[string]interface{}{
					"policies": []interface{}{Policy{
						ID: "test",
					}},
				},
			},
			want: map[string]Policy{
				"test": {
					ID: "test",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.session.CustomPolicies()
			if (err != nil) != tt.wantErr {
				t.Errorf("SessionState.CustomPolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SessionState.CustomPolicies() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessionState_SetCustomPolicies(t *testing.T) {

	policies := []Policy{{ID: "test"}}

	t.Run("nil-metadata", func(t *testing.T) {
		s := &SessionState{}
		s.SetCustomPolicies(nil)
		_, ok := s.MetaData["policies"]
		assert.True(t, ok)
	})

	t.Run("success-set-policy", func(t *testing.T) {
		s := &SessionState{MetaData: map[string]interface{}{}}
		s.SetCustomPolicies(policies)
		_, ok := s.MetaData["policies"]
		assert.True(t, ok)
	})

	t.Run("success-get-policy-back", func(t *testing.T) {
		s := &SessionState{MetaData: map[string]interface{}{}}
		s.SetCustomPolicies(policies)
		_, ok := s.MetaData["policies"]
		assert.True(t, ok)

		list, err := s.CustomPolicies()
		assert.NoError(t, err)

		_, ok = list["test"]
		assert.True(t, ok)
	})
}
