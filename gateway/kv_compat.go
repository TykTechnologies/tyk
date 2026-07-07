package gateway

import "strings"

// vaultDotToFragment converts a legacy vault key ("path/to/secret.field") to
// the new resolver notation ("path/to/secret#field"). The legacy Vault.Get
// required exactly one dot separating the secret path from the field name, so
// the split happens at the FIRST dot; keys without a dot pass through
// unchanged and are left for the resolver to reject or resolve as-is.
func vaultDotToFragment(key string) string {
	idx := strings.IndexByte(key, '.')
	if idx < 0 {
		return key
	}

	return key[:idx] + "#" + key[idx+1:]
}
