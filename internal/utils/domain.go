package utils

import "strings"

func OperationId(path, method string) string {
	return strings.TrimPrefix(path, "/") + strings.ToUpper(method)
}
