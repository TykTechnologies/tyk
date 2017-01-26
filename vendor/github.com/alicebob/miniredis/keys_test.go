package miniredis

import (
	"testing"
)

func TestKeysSel(t *testing.T) {
	// Helper to test the selection behind KEYS
	// pattern -> cases -> should match?
	for pat, chk := range map[string]map[string]bool{
		"aap": {
			"aap":         true,
			"aapnoot":     false,
			"nootaap":     false,
			"nootaapnoot": false,
			"AAP":         false,
		},
		"aap*": {
			"aap":         true,
			"aapnoot":     true,
			"nootaap":     false,
			"nootaapnoot": false,
			"AAP":         false,
		},
		// No problem with regexp meta chars?
		"(?:a)ap*": {
			"(?:a)ap!": true,
			"aap":      false,
		},
		"*aap*": {
			"aap":         true,
			"aapnoot":     true,
			"nootaap":     true,
			"nootaapnoot": true,
			"AAP":         false,
			"a_a_p":       false,
		},
		`\*aap*`: {
			"*aap":     true,
			"aap":      false,
			"*aapnoot": true,
			"aapnoot":  false,
		},
		`aa?`: {
			"aap":  true,
			"aal":  true,
			"aaf":  true,
			"aa?":  true,
			"aap!": false,
		},
		`aa\?`: {
			"aap":  false,
			"aa?":  true,
			"aa?!": false,
		},
		"aa[pl]": {
			"aap":  true,
			"aal":  true,
			"aaf":  false,
			"aa?":  false,
			"aap!": false,
		},
		"[ab]a[pl]": {
			"aap":  true,
			"aal":  true,
			"bap":  true,
			"bal":  true,
			"aaf":  false,
			"cap":  false,
			"aa?":  false,
			"aap!": false,
		},
		`\[ab\]`: {
			"[ab]": true,
			"a":    false,
		},
		`[\[ab]`: {
			"[": true,
			"a": true,
			"b": true,
			"c": false,
			"]": false,
		},
		`[\[\]]`: {
			"[": true,
			"]": true,
			"c": false,
		},
		`\\ap`: {
			`\ap`:  true,
			`\\ap`: false,
		},
		// Escape a normal char
		`\foo`: {
			`foo`:  true,
			`\foo`: false,
		},
	} {
		patRe := patternRE(pat)
		if patRe == nil {
			t.Errorf("'%v' won't match anything. Didn't expect that.\n", pat)
			continue
		}
		for key, expected := range chk {
			match := patRe.MatchString(key)
			if expected != match {
				t.Errorf("'%v' -> '%v'. Matches %v, should %v\n", pat, key, match, expected)
			}
		}
	}

	// Patterns which won't match anything.
	for _, pat := range []string{
		`ap[\`, // trailing \ in char class
		`ap[`,  // open char class
		`[]ap`, // empty char class
		`ap\`,  // trailing \
	} {
		if patternRE(pat) != nil {
			t.Errorf("'%v' will match something. Didn't expect that.\n", pat)
		}
	}
}
