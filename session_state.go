package main

import (
	"github.com/TykTechnologies/tyk/auth"
)

// This stub is part of a refactor, please see auth/session_state for the Session objects aliased below.

const (
	HashPlainText = auth.HashPlainText
	HashBCrypt    = auth.HashBCrypt
)

type AccessSpec = auth.AccessSpec
type AccessDefinition = auth.AccessDefinition
type SessionState = auth.SessionState


