//go:build race
// +build race

package test

func IsRaceEnabled() bool {
	return true
}
