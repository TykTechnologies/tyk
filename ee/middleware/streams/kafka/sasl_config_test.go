package kafka

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSASLConfigBuildsAllSupportedMechanisms(t *testing.T) {
	reader, err := parseAcknowledgmentTestReader(t, `
sasl:
  - mechanism: PLAIN
    username: plain-user
    password: plain-pass
  - mechanism: OAUTHBEARER
    token: oauth-token
    extensions: {tenant: tyk}
  - mechanism: SCRAM-SHA-256
    username: scram256-user
    password: scram256-pass
  - mechanism: SCRAM-SHA-512
    username: scram512-user
    password: scram512-pass
`)
	require.NoError(t, err)
	require.Len(t, reader.saslConfs, 4)
	require.Equal(t, "PLAIN", reader.saslConfs[0].Name())
	require.Equal(t, "OAUTHBEARER", reader.saslConfs[1].Name())
	require.Equal(t, "SCRAM-SHA-256", reader.saslConfs[2].Name())
	require.Equal(t, "SCRAM-SHA-512", reader.saslConfs[3].Name())
}

func TestSASLConfigRejectsUnknownAndIncompleteMechanisms(t *testing.T) {
	for _, tc := range []struct{ name, yaml, contains string }{
		{"unknown", "\nsasl:\n  - mechanism: KERBEROS\n", "unknown mechanism"},
		{"plain missing password", "\nsasl:\n  - mechanism: PLAIN\n    username: user\n", "password"},
		{"indexed error", "\nsasl:\n  - mechanism: none\n  - mechanism: SCRAM-SHA-256\n    username: user\n", "mechanism 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAcknowledgmentTestReader(t, tc.yaml)
			require.ErrorContains(t, err, tc.contains)
		})
	}
}
