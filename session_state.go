package main

import (
	"github.com/TykTechnologies/tyk/session"
)

// This stub is part of a refactor, please see auth/session_state for the Session objects aliased below.

const (
	HashPlainText = session.HashPlainText
	HashBCrypt    = session.HashBCrypt
)

type AccessSpec = session.AccessSpec
type AccessDefinition = session.AccessDefinition
type SessionState = session.SessionState


