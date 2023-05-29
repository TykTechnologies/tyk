package model

import (
	"github.com/TykTechnologies/goverify"
	"github.com/TykTechnologies/tyk/config"

	"github.com/sirupsen/logrus"
)

type GatewayInterface interface {
	// general
	GetConfig() config.Config
	Logger() *logrus.Logger

	// auth
	GenerateToken(string, string, ...string) string
	ObfuscateKey(string) string

	// notifications
	Notify(Notification)
	GetNotificationVerifier(Notification) goverify.Verifier
}
