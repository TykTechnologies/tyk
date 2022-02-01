package jsonschema

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var showDebug = os.Getenv("JSON_SCHEMA_DEBUG") == "1"

// schemaDebug provides a logging interface
// which is off by defauly but can be activated
// for debuging purposes
func schemaDebug(message string, args ...interface{}) {
	if showDebug {
		if message[len(message)-1] != '\n' {
			message += "\n"
		}
		fmt.Printf(message, args...)
	}
}

// SafeResolveURL resolves a string url against the current context url
func SafeResolveURL(ctxURL, resURL string) (string, error) {
	cu, err := url.Parse(ctxURL)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(resURL)
	if err != nil {
		return "", err
	}
	resolvedURL := cu.ResolveReference(u)
	if resolvedURL.Scheme == "file" && cu.Scheme != "file" {
		return "", fmt.Errorf("cannot access file resources from network context")
	}
	resolvedURLString := resolvedURL.String()
	return resolvedURLString, nil
}

// IsLocalSchemaID validates if a given id is a local id
func IsLocalSchemaID(id string) bool {
	splitID := strings.Split(id, "#")
	if len(splitID) > 1 && len(splitID[0]) > 0 && splitID[0][0] != '#' {
		return false
	}
	return id != "#" && !strings.HasPrefix(id, "#/") && strings.Contains(id, "#")
}

// FetchSchema downloads and loads a schema from a remote location
func FetchSchema(ctx context.Context, uri string, schema *Schema) error {
	schemaDebug(fmt.Sprintf("[FetchSchema] Fetching: %s", uri))
	u, err := url.Parse(uri)
	if err != nil {
		return err
	}
	// TODO(arqu): support other schemas like file or ipfs
	if u.Scheme == "http" || u.Scheme == "https" {
		var req *http.Request
		if ctx != nil {
			req, _ = http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		} else {
			req, _ = http.NewRequest("GET", u.String(), nil)
		}
		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		if schema == nil {
			schema = &Schema{}
		}
		return json.Unmarshal(body, schema)
	}
	if u.Scheme == "file" {
		body, err := ioutil.ReadFile(u.Path)
		if err != nil {
			return err
		}
		if schema == nil {
			schema = &Schema{}
		}
		return json.Unmarshal(body, schema)
	}
	return fmt.Errorf("URI scheme %s is not supported for uri: %s", u.Scheme, uri)
}
