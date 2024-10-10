package policy

import "github.com/TykTechnologies/tyk/user"

// Repository is a storage encapsulating policy retrieval.
// Gateway implements this object to decouple this package.
type Repository interface {
	PolicyCount() int
	PolicyIDs() []string
	PolicyByID(string) (user.Policy, bool)
}
