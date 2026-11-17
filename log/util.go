package log

import "os"

func CoalesceEnvOr[T any, P interface {
	*T
	Parse(string) bool
}](fallback T, envNames ...string) T {

	for _, envName := range envNames {
		raw := os.Getenv(envName)
		if raw == "" {
			continue
		}

		var value T
		if P(&value).Parse(raw) {
			return value
		}
	}

	return fallback
}

func CoalesceValidEnv[T any, P interface {
	*T
	Parse(string) bool
	Valid() bool
}](envNames ...string) (T, bool) {

	for _, envName := range envNames {
		raw := os.Getenv(envName)
		if raw == "" {
			continue
		}

		var value T
		if P(&value).Parse(raw) {
			return value, true
		}
	}

	var zero T
	return zero, false
}
