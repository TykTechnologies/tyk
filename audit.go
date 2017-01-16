package main

import (
	"os"

	"github.com/facebookgo/pidfile"
)

type AuditHostDetails struct {
	Hostname string
	PID      int
}

var HostDetails AuditHostDetails

func GetHostDetails() {
	var err error
	if HostDetails.PID, err = pidfile.Read(); err != nil {
		log.Error("Failed ot get host pid: ", err)
	}

	if HostDetails.Hostname, err = os.Hostname(); err != nil {
		log.Error("Failed ot get hostname: ", err)
	}
}
