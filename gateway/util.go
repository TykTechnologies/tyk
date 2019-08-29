package gateway

// appendIfMissing appends the given new item to the given slice.
func appendIfMissing(slice []string, new string) []string {
	for _, item := range slice {
		if item == new {
			return slice
		}
	}
	return append(slice, new)
}

// contains checks whether the given slice contains the given item.
func contains(s []string, i string) bool {
	for _, a := range s {
		if a == i {
			return true
		}
	}
	return false
}
