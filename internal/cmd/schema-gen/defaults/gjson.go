package defaults

import (
	"encoding/json"

	"github.com/tidwall/gjson"
)

// SanitizeJSON will take a json []byte, parse it and clean up values
// that should be omitted, empty strings, boolean falses and other.
func SanitizeJSON(in []byte) ([]byte, error) {
	parsed := gjson.ParseBytes(in)
	cleaned := removeEmptyValues(parsed)
	return json.MarshalIndent(cleaned.Value(), "", "  ")
}

// Leonid Bugaev authored:
func removeEmptyValues(parsed gjson.Result) gjson.Result {
	// Recurse into nested structures
	if parsed.Type == gjson.JSON {
		if parsed.IsArray() {
			newObj := make([]interface{}, 0)
			parsed.ForEach(func(key, value gjson.Result) bool {
				if value.Type == gjson.JSON {
					newValue := removeEmptyValues(value)

					newObj = append(newObj, newValue.Value())
				} else {
					newObj = append(newObj, value.Value())
				}
				return true
			})
			if len(newObj) == 0 {
				return gjson.Result{}
			}

			marshaled, _ := json.Marshal(newObj) //nolint:errcheck,errchkjson

			return gjson.Parse(string(marshaled))
		} else {
			newObj := make(map[string]interface{})
			parsed.ForEach(func(key, value gjson.Result) bool {
				newValue := removeEmptyValues(value)

				if newValue.Exists() || (newValue.Type != gjson.JSON && newValue.String() != "") {
					newObj[key.String()] = newValue.Value()
				}
				return true
			})
			if len(newObj) == 0 {
				return gjson.Result{}
			}

			marshaled, _ := json.Marshal(newObj) //nolint:errcheck,errchkjson

			return gjson.Parse(string(marshaled))
		}
	}

	// Remove boolean values if they are false
	if parsed.Type == gjson.False {
		return gjson.Result{}
	}

	// Remove numeric values if they are 0
	if parsed.Type == gjson.Number && parsed.Float() == 0 {
		return gjson.Result{}
	}

	// Remove null values
	if parsed.Type == gjson.Null {
		return gjson.Result{}
	}

	// Remove string values if they are empty
	if parsed.Type == gjson.String && parsed.String() == "" {
		return gjson.Result{}
	}

	// Return the original value if it's not empty
	return parsed
}
