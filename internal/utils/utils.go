package utils

func AsPtr[V any](in V) *V {
	return &in
}
