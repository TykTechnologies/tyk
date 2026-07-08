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

// dollarSecretToKVRef converts a matched $secret_* token's key into the $kv{}
// reference the resolver understands, routing each legacy label to its
// registry store. The token regexes admit no '#', '{', '}' or ':' characters,
// so the key cannot alter the reference's structure.
func dollarSecretToKVRef(label, key string) string {
	switch label {
	case vaultLabel:
		return "$kv{vault:" + vaultDotToFragment(key) + "}"
	case consulLabel:
		return "$kv{consul:" + key + "}"
	case envLabel:
		return "$kv{env:" + key + "}"
	case secretsConfLabel:
		return "$kv{secrets:" + key + "}"
	case fileLabel:
		return "$kv{file:" + key + "}"
	default:
		return ""
	}
}
