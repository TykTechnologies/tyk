package gateway

import (
	"errors"
	"os"
)

// appendIfMissing ensures dest slice is unique with new items.
func appendIfMissing(src []string, in ...string) []string {
	// Use map for uniqueness
	srcMap := map[string]bool{}
	for _, v := range src {
		srcMap[v] = true
	}
	for _, v := range in {
		srcMap[v] = true
	}

	// Produce unique []string, maintain sort order
	uniqueSorted := func(src []string, keys map[string]bool) []string {
		result := make([]string, 0, len(keys))
		for _, v := range src {
			// append missing value
			if val := keys[v]; val {
				result = append(result, v)
				delete(keys, v)
			}
		}
		return result
	}

	// no new items from `in`
	if len(srcMap) == len(src) {
		return src
	}

	src = uniqueSorted(src, srcMap)
	in = uniqueSorted(in, srcMap)

	return append(src, in...)
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

func FileExist(filepath string) bool {
	if _, err := os.Stat(filepath); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}
