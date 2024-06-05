package model

// HostDetails contains information about a host machine,
// including its hostname, process ID (PID), and IP address.
type HostDetails struct {
	Hostname string
	PID      int
	Address  string
}
