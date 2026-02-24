package apidef

import (
	"errors"
	"regexp"
)

var (
	unicodeRegex = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	re2Regex     = regexp.MustCompile(`\\x\{([0-9a-fA-F]{4})}`)
)

// TransformUnicodeEscapesToRE2 takes a byte array containing a regular expression
// pattern and transforms ECMA-262 compliant Unicode escape sequences (`\uXXXX`)
// into a format that is compatible with Go's RE2 regex engine (`\x{XXXX}`).
// This is necessary because RE2 does not support the `\u` escape sequence but
// does support hexadecimal escapes, which can represent any Unicode code point.
// The function returns a new byte array with the transformed pattern.
func TransformUnicodeEscapesToRE2(data []byte) []byte {
	return unicodeRegex.ReplaceAllFunc(data, func(match []byte) []byte {
		res := make([]byte, 0, 8)
		res = append(res, `\x{`...)
		res = append(res, match[2:]...)
		res = append(res, `}`...)
		return res
	})
}

// RestoreUnicodeEscapesFromRE2 translates RE2-compatible hexadecimal escape
// sequences (`\x{XXXX}`) back to their original ECMA-262 compliant Unicode
// escape sequence representation (`\uXXXX`). This function is typically used
// when exporting an API definition or any other data structure where regex
// patterns were previously sanitized for internal use with Go's RE2 engine.
// It ensures that external consumers of the data receive the regex patterns
// in their original, more widely supported format.
func RestoreUnicodeEscapesFromRE2(data []byte) []byte {
	return re2Regex.ReplaceAllFunc(data, func(match []byte) []byte {
		res := make([]byte, 0, 6)
		res = append(res, `\u`...)
		res = append(res, match[3:7]...)
		return res
	})
}

// RestoreUnicodeEscapesInError takes an error and applies the
// RestoreUnicodeEscapesInRegexp transformation to its message. For example,
// it converts RE2-compatible escapes like `\x{0041}` back to `\u0041`.
// It returns a new error with the transformed message. If the input error is nil,
// it returns nil.
func RestoreUnicodeEscapesInError(err error) error {
	if err == nil {
		return nil
	}

	originalMsgBytes := []byte(err.Error())
	restoredMsgBytes := RestoreUnicodeEscapesFromRE2(originalMsgBytes)

	return errors.New(string(restoredMsgBytes))
}
