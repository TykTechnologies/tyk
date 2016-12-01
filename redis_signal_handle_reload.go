package main

import (
	"github.com/TykTechnologies/logrus"
)

func HandleReloadMsg() {
	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Info("Reloading endpoints")
	ReloadURLStructure()
}
