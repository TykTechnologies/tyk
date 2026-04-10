package policy

import (
	"slices"

	"github.com/TykTechnologies/tyk/user"
)

// MergeAllowedURLs will merge s1 and s2 to produce a merged result.
// It maintains order of keys in s1 and s2 as they are seen.
// If the result is an empty set, nil is returned.
func MergeAllowedURLs(s1, s2 []user.AccessSpec) []user.AccessSpec {
	order := []string{}
	merged := map[string][]string{}

	// Loop input sets and merge through a map.
	for _, src := range [][]user.AccessSpec{s1, s2} {
		for _, r := range src {
			url := r.URL
			v, ok := merged[url]
			if !ok {
				// First time we see the spec
				merged[url] = r.Methods

				// Maintain order
				order = append(order, url)

				continue
			}
			merged[url] = appendIfMissing(v, r.Methods...)
		}
	}

	// Early exit without allocating.
	if len(order) == 0 {
		return nil
	}

	// Provide results in desired order.
	result := make([]user.AccessSpec, 0, len(order))
	for _, key := range order {
		spec := user.AccessSpec{
			Methods: merged[key],
			URL:     key,
		}
		result = append(result, spec)
	}
	return result
}

// appendIfMissing ensures dest slice is unique with new items.
func appendIfMissing(dest []string, in ...string) []string {
	for _, v := range in {
		if slices.Contains(dest, v) {
			continue
		}
		dest = append(dest, v)
	}
	return dest
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
