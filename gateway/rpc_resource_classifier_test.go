package gateway

import (
	"reflect"
	"testing"
)

// TestDefaultRPCResourceClassifier_classify tests the classify function.
func TestDefaultRPCResourceClassifier_classify(t *testing.T) {
	tests := []struct {
		name                         string
		keys                         []string
		expectedStandardKeys         map[string]string
		expectedKeysToReset          map[string]bool
		expectedOauthTokensToRevoke  map[string]string
		expectedOauthClientsToRevoke map[string]string
		expectedCertsActions         map[string]string
		expectedOauthClientsActions  map[string]string
		// Add expected maps for the other return values.
	}{
		{
			name: "Test with mixed keys",
			keys: []string{
				"key1:resetQuota",
				"key2:hashed",
				"cert1:CertificateAdded",
				"cert2:CertificateAdded",
				"token1:oAuthRevokeToken",
				"token3:oAuthRevokeRefreshToken",
				"client1:revoke_all_tokens",
				"client2:OauthClientAdded",
				"client3:OauthClientRemoved",
				"client4:OauthClientUpdated",
				"simpleKey",
			},
			expectedStandardKeys: map[string]string{
				"key1:resetQuota": "key1:resetQuota",
				"key2:hashed":     "key2:hashed",
				"simpleKey":       "simpleKey",
			},
			expectedKeysToReset: map[string]bool{
				"key1": true,
			},
			expectedOauthTokensToRevoke: map[string]string{
				"token1": "token1:oAuthRevokeToken",
				"token3": "token3:oAuthRevokeRefreshToken",
			},
		},
		// Add more test cases.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DefaultRPCResourceClassifier{}
			standardKeys, keysToReset, tokensToBeRevoked, _, _, _ := d.classify(tt.keys)
			//standardKeys, keysToReset, tokensToBeRevoked, clientsToRevoke, certs, oauthClients := d.classify(tt.keys)
			if !reflect.DeepEqual(standardKeys, tt.expectedStandardKeys) {
				t.Errorf("classify() standardKeys = %v, want %v", standardKeys, tt.expectedStandardKeys)
			}
			if !reflect.DeepEqual(keysToReset, tt.expectedKeysToReset) {
				t.Errorf("classify() keysToReset = %v, want %v", keysToReset, tt.expectedKeysToReset)
			}
			if !reflect.DeepEqual(tokensToBeRevoked, tt.expectedOauthTokensToRevoke) {
				t.Errorf("classify() oauthTokensToRevoke = %v, want %v", tokensToBeRevoked, tt.expectedOauthTokensToRevoke)
			}
		})
	}
}

/*
A key that triggers the ResetQuota action:

"key1:resetQuota"
A key that indicates a HashedKey action:

"key2:hashed"
Keys for both CertificateRemoved and CertificateAdded actions:

"cert1:CertificateRemoved"
"cert2:CertificateAdded"
Keys for OAuth token actions (OAuthRevokeToken, OAuthRevokeAccessToken, OAuthRevokeRefreshToken, OAuthRevokeAllTokens):

"token1:OAuthRevokeToken"
"token2:OAuthRevokeAccessToken"
"token3:OAuthRevokeRefreshToken"
"client1:revoke_all_tokens"
Keys for Oauth client actions (OauthClientAdded, OauthClientRemoved, OauthClientUpdated):

"client2:OauthClientAdded"
"client3:OauthClientRemoved"
"client4:OauthClientUpdated"
A key that does not match any case in the switch statement (to test the default case):

"unknownAction"
A key without a colon to test the else branch outside the switch:

"simpleKey"
*/
