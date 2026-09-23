package policy

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/TykTechnologies/tyk/user"
)

// MergeAllowedURLs will merge s1 and s2 to produce a merged result.
// It maintains order of keys in s1 and s2 as they are seen.
// If the result is an empty set, nil is returned.
//
// Specs are merged per URL and set of conditions: two specs granting the same
// URL under different conditions stay separate entries, so that each is
// evaluated on its own and the merge widens access rather than narrowing it.
func MergeAllowedURLs(s1, s2 []user.AccessSpec) []user.AccessSpec {
	order := []string{}
	merged := map[string]user.AccessSpec{}

	// Loop input sets and merge through a map.
	for _, src := range [][]user.AccessSpec{s1, s2} {
		for _, r := range src {
			key := allowedURLKey(r)
			v, ok := merged[key]
			if !ok {
				// First time we see the spec
				merged[key] = r

				// Maintain order
				order = append(order, key)

				continue
			}
			v.Methods = appendIfMissing(v.Methods, r.Methods...)
			merged[key] = v
		}
	}

	// Early exit without allocating.
	if len(order) == 0 {
		return nil
	}

	// Provide results in desired order.
	result := make([]user.AccessSpec, 0, len(order))
	for _, key := range order {
		result = append(result, merged[key])
	}
	return result
}

// allowedURLKey identifies an access spec by everything except its methods,
// which are what the merge unions together.
func allowedURLKey(spec user.AccessSpec) string {
	if len(spec.Conditions) == 0 {
		return spec.URL
	}

	// Conditions hold maps, so compare them by their JSON encoding, which
	// encoding/json emits with sorted keys and is therefore stable.
	conditions, err := json.Marshal(spec.Conditions)
	if err != nil {
		// Unreachable for the plain data in AccessCondition, but if it ever
		// happens, keep the spec distinct rather than merging it by URL alone.
		return spec.URL + "\x00" + fmt.Sprintf("%v", spec.Conditions)
	}

	return spec.URL + "\x00" + string(conditions)
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
