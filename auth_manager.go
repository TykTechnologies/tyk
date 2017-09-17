package main

import (
	"github.com/TykTechnologies/tyk/auth"
	"github.com/TykTechnologies/tyk/authorization_handler"
	"github.com/TykTechnologies/tyk/session_handler"
	"github.com/TykTechnologies/tyk/keygen"
)

type AuthorisationHandler = authorization_handler.AuthorisationHandler
type SessionHandler = session_handler.SessionHandler
type DefaultAuthorisationManager = auth.DefaultAuthorisationManager
type DefaultSessionManager = auth.DefaultSessionManager
type DefaultKeyGenerator = keygen.DefaultKeyGenerator