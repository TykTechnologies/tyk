package auth

func ObfuscateKeyString(keyName string) string {
	obfuscated := "--"

	if len(keyName) > 4 {
		obfuscated = "****" + keyName[len(keyName)-4:]
	}

	return obfuscated
}
