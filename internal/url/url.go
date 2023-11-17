package url

import "net/url"

type URL = url.URL

// QueryHas checks whether a given key is set.
func QueryHas(v url.Values, key string) bool {
	_, ok := v[key]
	return ok
}
