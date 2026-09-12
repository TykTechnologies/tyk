package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// DecodeDiscoveryObject decodes one complete, bounded JSON object. It rejects
// duplicate members and non-canonical spellings of fields whose identity is
// security-sensitive to discovery consumers. Unknown extension fields remain
// available in the returned map.
func DecodeDiscoveryObject(body []byte, limit int64, ownedFields ...string) (map[string]any, error) {
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("discovery document exceeds %d bytes", limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("discovery document must be a JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("discovery document contains an invalid member name")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("discovery document contains duplicate member %q", name)
		}
		seen[name] = struct{}{}
		for _, owned := range ownedFields {
			if strings.EqualFold(name, owned) && name != owned {
				return nil, fmt.Errorf("discovery document member %q must use canonical spelling %q", name, owned)
			}
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("discovery document has trailing JSON data")
	}

	decoder = json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var result map[string]any
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}
