// Package condition provides a simple expression language for evaluating
// conditions against HTTP requests and session metadata. Expressions are
// compiled once and evaluated per-request with zero allocations for
// common operations (method, path, header checks).
package condition

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// ConditionFunc evaluates a compiled condition against a request and session metadata.
// It returns true if the condition is satisfied.
// The metadata parameter corresponds to session.MetaData.
type ConditionFunc func(r *http.Request, metadata map[string]interface{}) bool

// ContextDataKey is the context key used to retrieve context data from requests.
// It must be set by the consuming package (e.g. gateway) to match the key used
// to store context data (ctx.ContextData).
var ContextDataKey any

// Compile parses an expression string and returns a ConditionFunc.
// An empty expression returns a function that always returns true.
// Compile returns an error for invalid syntax, unknown namespaces,
// or invalid regex patterns in matches operators.
func Compile(expr string) (ConditionFunc, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return func(_ *http.Request, _ map[string]interface{}) bool { return true }, nil
	}

	l := newLexer(expr)
	tokens, err := l.tokenize()
	if err != nil {
		return nil, fmt.Errorf("condition: %w", err)
	}

	p := newParser(tokens)
	node, err := p.parse()
	if err != nil {
		return nil, fmt.Errorf("condition: %w", err)
	}

	fn, err := compile(node)
	if err != nil {
		return nil, fmt.Errorf("condition: %w", err)
	}

	return fn, nil
}

// compile turns an AST node into a ConditionFunc.
func compile(node astNode) (ConditionFunc, error) {
	switch n := node.(type) {
	case *binaryNode:
		return compileBinary(n)
	case *notNode:
		inner, err := compile(n.operand)
		if err != nil {
			return nil, err
		}
		return func(r *http.Request, m map[string]interface{}) bool {
			return !inner(r, m)
		}, nil
	case *comparisonNode:
		return compileComparison(n)
	default:
		return nil, fmt.Errorf("unexpected node type %T", node)
	}
}

func compileBinary(n *binaryNode) (ConditionFunc, error) {
	left, err := compile(n.left)
	if err != nil {
		return nil, err
	}
	right, err := compile(n.right)
	if err != nil {
		return nil, err
	}

	switch n.op {
	case tokenAnd:
		return func(r *http.Request, m map[string]interface{}) bool {
			return left(r, m) && right(r, m)
		}, nil
	case tokenOr:
		return func(r *http.Request, m map[string]interface{}) bool {
			return left(r, m) || right(r, m)
		}, nil
	default:
		return nil, fmt.Errorf("unknown binary op: %v", n.op)
	}
}

func compileComparison(n *comparisonNode) (ConditionFunc, error) {
	accessor, err := buildAccessor(n.left)
	if err != nil {
		return nil, err
	}

	switch n.op {
	case tokenEq:
		val := n.right
		return func(r *http.Request, m map[string]interface{}) bool {
			return accessor(r, m) == val
		}, nil
	case tokenNeq:
		val := n.right
		return func(r *http.Request, m map[string]interface{}) bool {
			return accessor(r, m) != val
		}, nil
	case tokenContains:
		val := n.right
		return func(r *http.Request, m map[string]interface{}) bool {
			return strings.Contains(accessor(r, m), val)
		}, nil
	case tokenMatches:
		re, err := regexp.Compile(n.right)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", n.right, err)
		}
		return func(r *http.Request, m map[string]interface{}) bool {
			return re.MatchString(accessor(r, m))
		}, nil
	default:
		return nil, fmt.Errorf("unknown comparison op: %v", n.op)
	}
}

// accessorFunc extracts a string value from a request and session metadata.
type accessorFunc func(r *http.Request, metadata map[string]interface{}) string

func buildAccessor(ref accessorRef) (accessorFunc, error) {
	switch ref.namespace {
	case "request":
		return buildRequestAccessor(ref)
	case "context":
		key := ref.key
		return func(r *http.Request, _ map[string]interface{}) string {
			if r == nil || ContextDataKey == nil {
				return ""
			}
			data, _ := r.Context().Value(ContextDataKey).(map[string]interface{})
			if data == nil {
				return ""
			}
			v, _ := data[key].(string)
			return v
		}, nil
	case "session":
		if ref.field != "metadata" {
			return nil, fmt.Errorf("unknown session field %q", ref.field)
		}
		key := ref.key
		return func(_ *http.Request, m map[string]interface{}) string {
			if m == nil {
				return ""
			}
			v, _ := m[key].(string)
			return v
		}, nil
	default:
		return nil, fmt.Errorf("unknown namespace %q", ref.namespace)
	}
}

func buildRequestAccessor(ref accessorRef) (accessorFunc, error) {
	switch ref.field {
	case "method":
		return func(r *http.Request, _ map[string]interface{}) string {
			if r == nil {
				return ""
			}
			return r.Method
		}, nil
	case "path":
		return func(r *http.Request, _ map[string]interface{}) string {
			if r == nil {
				return ""
			}
			return r.URL.Path
		}, nil
	case "headers":
		key := ref.key
		return func(r *http.Request, _ map[string]interface{}) string {
			if r == nil {
				return ""
			}
			return r.Header.Get(key)
		}, nil
	case "params":
		key := ref.key
		return func(r *http.Request, _ map[string]interface{}) string {
			if r == nil {
				return ""
			}
			return r.URL.Query().Get(key)
		}, nil
	default:
		return nil, fmt.Errorf("unknown request field %q", ref.field)
	}
}
