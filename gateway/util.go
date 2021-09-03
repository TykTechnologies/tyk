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

// intersection gets intersection of the given two slices.
func intersection(a []string, b []string) (inter []string) {
	m := make(map[string]bool)

	for _, item := range a {
		m[item] = true
	}

	for _, item := range b {
		if _, ok := m[item]; ok {
			inter = append(inter, item)
		}
	}

	return
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

// greaterThanFloat64 checks whether first float64 value is bigger than second float64 value.
// -1 means infinite and the biggest value.
func greaterThanFloat64(first, second float64) bool {
	if first == -1 {
		return true
	}

	if second == -1 {
		return false
	}

	return first > second
}

// greaterThanInt64 checks whether first int64 value is bigger than second int64 value.
// -1 means infinite and the biggest value.
func greaterThanInt64(first, second int64) bool {
	if first == -1 {
		return true
	}

	if second == -1 {
		return false
	}

	return first > second
}

// greaterThanInt checks whether first int value is bigger than second int value.
// -1 means infinite and the biggest value.
func greaterThanInt(first, second int) bool {
	if first == -1 {
		return true
	}

	if second == -1 {
		return false
	}

	return first > second
}
// remove duplicate strings from string slice
func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
