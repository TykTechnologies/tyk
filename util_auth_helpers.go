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

func stripSignature(token string) string {
	thisToken := token
	if strings.HasPrefix(token, "Signature") {
		thisToken = strings.Replace(token, "Signature", "", 1)
	}

	if strings.HasPrefix(token, "signature") {
		thisToken = strings.Replace(thisToken, "signature", "", 1)
	}

	thisToken = strings.TrimSpace(thisToken)
	return thisToken
}
