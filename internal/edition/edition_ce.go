//go:build !ee

package edition

func GetEdition() string {
	return "Community"
}
