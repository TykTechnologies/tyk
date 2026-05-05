//go:build reqproof_proof

package policy

// reqproof:lemma apply_nil_storage_returns_err
func apply_nil_storage_returns_err(t *Service) error {
	if t.storage == nil {
		return ErrNilPolicyStore
	}
	return nil
}
