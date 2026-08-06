package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVaultDotToFragment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "single dot splits path from field",
			key:  "db/creds.password",
			want: "db/creds#password",
		},
		{
			name: "no dot passes through unchanged",
			key:  "db/creds",
			want: "db/creds",
		},
		{
			name: "multi-segment path keeps all segments",
			key:  "secret/data/db/creds.password",
			want: "secret/data/db/creds#password",
		},
		{
			// Legacy Vault.Get required exactly one dot and errored otherwise,
			// so no working legacy key has two dots.
			name: "multiple dots split at the first",
			key:  "db.creds.password",
			want: "db#creds.password",
		},
		{
			name: "empty key passes through unchanged",
			key:  "",
			want: "",
		},
		{
			name: "leading dot yields empty path and bare fragment",
			key:  ".field",
			want: "#field",
		},
		{
			name: "trailing dot yields empty fragment",
			key:  "db/creds.",
			want: "db/creds#",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, vaultDotToFragment(tc.key))
		})
	}
}

func TestDollarSecretToKVRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		label string
		key   string
		want  string
	}{
		{name: "conf", label: secretsConfLabel, key: "db_password", want: "kv://secrets/db_password"},
		{name: "env", label: envLabel, key: "db_password", want: "kv://env/db_password"},
		{name: "consul", label: consulLabel, key: "app/db/password", want: "kv://consul/app/db/password"},
		{name: "file", label: fileLabel, key: "certs/key.pem", want: "kv://file/certs/key.pem"},
		{
			name:  "vault key dot becomes a fragment",
			label: vaultLabel,
			key:   "db/creds.password",
			want:  "kv://vault/db/creds#password",
		},
		{name: "unknown label yields no reference", label: metaLabel, key: "x", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, dollarSecretToKVRef(tc.label, tc.key))
		})
	}
}
