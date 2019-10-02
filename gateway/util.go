package gateway

// appendIfMissing appends the given new item to the given slice.
func appendIfMissing(slice []string, newSlice ...string) []string {
	for _, new := range newSlice {
		found := false
		for _, item := range slice {
			if item == new {
				continue
			}
			found = true
		}

		if !found {
			slice = append(slice, new)
		}
	}

	return slice
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
