package main

import (
	"syscall"
)

func ReloadConfiguration() {
	myPID := HostDetails.PID
	if myPID == 0 {
		log.Error("No PID found, cannot reload")
		return
	}

	log.Info("Sending reload signal to PID: ", myPID)

	callErr := syscall.Kill(myPID, syscall.SIGUSR2)
	if callErr != nil {
		log.Error("Process reload failed: ", callErr)
	}
}
