package oas

import "sort"

// Header holds a header name and value pair.
type Header struct {
	// Name is the name of the header.
	Name string `bson:"name" json:"name"`
	// Value is the value of the header.
	Value string `bson:"value" json:"value"`
}

// Headers is an array of Header.
type Headers []Header

// Map transforms Headers into a map.
func (hs *Headers) Map() map[string]string {
	if hs == nil {
		return map[string]string{}
	}

	var headersMap = make(map[string]string, len(*hs))
	for _, h := range *hs {
		headersMap[h.Name] = h.Value
	}

	return headersMap
}

// Add new header entry.
func (hs *Headers) Add(hdr, value string) {
	*hs = append(*hs, Header{Name: hdr, Value: value})
}

// NewHeaders creates Headers from in map.
func NewHeaders(in map[string]string) Headers {
	var headers = make(Headers, 0, len(in))

	for k, v := range in {
		headers = append(headers, Header{Name: k, Value: v})
	}

	sort.Slice(headers, func(i, j int) bool {
		return headers[i].Name < headers[j].Name
	})
	return headers
}
