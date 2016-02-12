package main

import (
  "strings"
)

func stripBearer(token string) string {
	thisToken := strings.Replace(token, "Bearer", "", 1)
	thisToken = strings.Replace(thisToken, "bearer", "", 1)
	thisToken = strings.TrimSpace(thisToken)
	return thisToken
}
