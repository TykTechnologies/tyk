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
