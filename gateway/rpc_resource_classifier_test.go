package gateway

import (
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestRPCResourceClassifierAPIKeys(t *testing.T) {
	tests := []struct {
		name                 string
		keys                 []string
		expectedStandardKeys map[string]KeyEvent
	}{
		// ToDO: add more use-cases
		{
			name: "Test API Keys",
			keys: []string{
				"key1:resetQuota",
				"key2:hashed",
				"eyJvcmciOiI2NTVkZmE2Y2Q0YWVmYzA1YzcyOThkOTMiLCJpZCI6Im15X2N1c3RvbV9rZXkxIiwiaCI6Im11cm11cjY0In0=",
			},
			expectedStandardKeys: map[string]KeyEvent{
				"key1": {
					KeyID:      "key1",
					ResetQuota: true,
				},
				"key2": {
					KeyID:  "key2",
					Hashed: true,
				},
				"eyJvcmciOiI2NTVkZmE2Y2Q0YWVmYzA1YzcyOThkOTMiLCJpZCI6Im15X2N1c3RvbV9rZXkxIiwiaCI6Im11cm11cjY0In0=": {
					KeyID: "eyJvcmciOiI2NTVkZmE2Y2Q0YWVmYzA1YzcyOThkOTMiLCJpZCI6Im15X2N1c3RvbV9rZXkxIiwiaCI6Im11cm11cjY0In0=",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &DefaultRPCResourceClassifier{}
			standardKeysEvents, oauthEvents, certEvents := d.classify(tc.keys)

			if !reflect.DeepEqual(standardKeysEvents, tc.expectedStandardKeys) {
				t.Errorf("classify() standardKeys = %v, want %v", standardKeysEvents, tc.expectedStandardKeys)
			}

			assert.Equal(t, []OauthEvent{}, oauthEvents)
			assert.Len(t, certEvents, 0, "certs events should be empty")
		})
	}
}

func TestRPCResourceClassifierOAuthEvents(t *testing.T) {
	tests := []struct {
		name                string
		keys                []string
		expectedOauthEvents []OauthEvent
	}{
		// ToDO: add more use-cases
		{
			name: "Test OAuth Events",
			keys: []string{
				"token1:apiId:oAuthRevokeToken",
				"token3:apiId:oAuthRevokeRefreshToken",
				"apiId:client1:client_s3cr3t:revoke_all_tokens",
				"apiId.client2.orgId:OauthClientAdded",
				"apiId.client3.orgId:OauthClientRemoved",
				"apiId.client4.orgId:OauthClientUpdated",
			},
			expectedOauthEvents: []OauthEvent{
				{
					EventType: "oAuthRevokeToken",
					Token:     "token1",
					ApiId:     "apiId",
				},
				{
					EventType: "oAuthRevokeRefreshToken",
					Token:     "token3",
					ApiId:     "apiId",
				},
				{
					EventType:    "revoke_all_tokens",
					ApiId:        "apiId",
					ClientId:     "client1",
					ClientSecret: "client_s3cr3t",
				},
				{
					EventType: "OauthClientAdded",
					ApiId:     "apiId",
					ClientId:  "client2",
					OrgId:     "orgId",
				},
				{
					EventType: "OauthClientRemoved",
					ApiId:     "apiId",
					ClientId:  "client3",
					OrgId:     "orgId",
				},
				{
					EventType: "OauthClientUpdated",
					ApiId:     "apiId",
					ClientId:  "client4",
					OrgId:     "orgId",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &DefaultRPCResourceClassifier{}
			standardKeysEvents, oauthEvents, certEvents := d.classify(tc.keys)

			if !reflect.DeepEqual(oauthEvents, tc.expectedOauthEvents) {
				t.Errorf("classify() oauth Events = %v, want %v", oauthEvents, tc.expectedOauthEvents)
			}

			assert.Len(t, standardKeysEvents, 0, "standard keys events should be empty")
			assert.Len(t, certEvents, 0, "certs events should be empty")
		})
	}

}

func TestRPCResourceClassifierCertEvents(t *testing.T) {
	tests := []struct {
		name                 string
		keys                 []string
		expectedCertsActions map[string]string
	}{
		// ToDO: add more use-cases
		{
			name: "Test Certificate Events",
			keys: []string{
				"cert1:CertificateAdded",
				"cert2:CertificateAdded",
				"cert2:CertificateRemoved:unvalid",
			},
			expectedCertsActions: map[string]string{
				"cert1": "CertificateAdded",
				"cert2": "CertificateAdded",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &DefaultRPCResourceClassifier{}
			standardKeysEvents, oauthEvents, certEvents := d.classify(tc.keys)

			if !reflect.DeepEqual(certEvents, tc.expectedCertsActions) {
				t.Errorf("classify() certs Events = %v, want %v", oauthEvents, tc.expectedCertsActions)
			}

			assert.Len(t, standardKeysEvents, 0, "standard keys events should be empty")
			assert.Len(t, oauthEvents, 0, "oauth events should be empty")
		})
	}
}
