package main

import (
	"github.com/Sirupsen/logrus"
)

func HandleReloadMsg() {
	log.WithFields(logrus.Fields{
		"prefix": "pub-sub",
	}).Info("Reloading endpoints")
	ReloadURLStructure()
}
