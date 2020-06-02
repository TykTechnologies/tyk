//go:generate stringer -type=IdentKeyword

// Package identkeyword contains all possible keywords for GraphQL identifiers
package identkeyword

type IdentKeyword int

const (
	UNDEFINED IdentKeyword = iota
	ON
	TRUE
	FALSE
	NULL
	QUERY
	MUTATION
	SUBSCRIPTION
	FRAGMENT
	IMPLEMENTS
	SCHEMA
	SCALAR
	TYPE
	INTERFACE
	UNION
	ENUM
	INPUT
	DIRECTIVE
	EXTEND
)

func KeywordFromLiteral(literal []byte) IdentKeyword {
	switch len(literal) {
	case 2:
		if literal[0] == 'o' && literal[1] == 'n' {
			return ON
		}
	case 4:
		if literal[0] == 'n' && literal[1] == 'u' && literal[2] == 'l' && literal[3] == 'l' {
			return NULL
		}
		if literal[0] == 'e' && literal[1] == 'n' && literal[2] == 'u' && literal[3] == 'm' {
			return ENUM
		}
		if literal[0] == 't' {
			if literal[1] == 'r' && literal[2] == 'u' && literal[3] == 'e' {
				return TRUE
			}
			if literal[1] == 'y' && literal[2] == 'p' && literal[3] == 'e' {
				return TYPE
			}
		}
	case 5:
		if literal[0] == 'f' && literal[1] == 'a' && literal[2] == 'l' && literal[3] == 's' && literal[4] == 'e' {
			return FALSE
		}
		if literal[0] == 'u' && literal[1] == 'n' && literal[2] == 'i' && literal[3] == 'o' && literal[4] == 'n' {
			return UNION
		}
		if literal[0] == 'q' && literal[1] == 'u' && literal[2] == 'e' && literal[3] == 'r' && literal[4] == 'y' {
			return QUERY
		}
		if literal[0] == 'i' && literal[1] == 'n' && literal[2] == 'p' && literal[3] == 'u' && literal[4] == 't' {
			return INPUT
		}
	case 6:
		if literal[0] == 'e' && literal[1] == 'x' && literal[2] == 't' && literal[3] == 'e' && literal[4] == 'n' && literal[5] == 'd' {
			return EXTEND
		}
		if literal[0] == 's' {
			if literal[1] == 'c' && literal[2] == 'h' && literal[3] == 'e' && literal[4] == 'm' && literal[5] == 'a' {
				return SCHEMA
			}
			if literal[1] == 'c' && literal[2] == 'a' && literal[3] == 'l' && literal[4] == 'a' && literal[5] == 'r' {
				return SCALAR
			}
		}
	case 8:
		if literal[0] == 'm' && literal[1] == 'u' && literal[2] == 't' && literal[3] == 'a' && literal[4] == 't' && literal[5] == 'i' && literal[6] == 'o' && literal[7] == 'n' {
			return MUTATION
		}
		if literal[0] == 'f' && literal[1] == 'r' && literal[2] == 'a' && literal[3] == 'g' && literal[4] == 'm' && literal[5] == 'e' && literal[6] == 'n' && literal[7] == 't' {
			return FRAGMENT
		}
	case 9:
		if literal[0] == 'i' && literal[1] == 'n' && literal[2] == 't' && literal[3] == 'e' && literal[4] == 'r' && literal[5] == 'f' && literal[6] == 'a' && literal[7] == 'c' && literal[8] == 'e' {
			return INTERFACE
		}
		if literal[0] == 'd' && literal[1] == 'i' && literal[2] == 'r' && literal[3] == 'e' && literal[4] == 'c' && literal[5] == 't' && literal[6] == 'i' && literal[7] == 'v' && literal[8] == 'e' {
			return DIRECTIVE
		}
	case 10:
		if literal[0] == 'i' && literal[1] == 'm' && literal[2] == 'p' && literal[3] == 'l' && literal[4] == 'e' && literal[5] == 'm' && literal[6] == 'e' && literal[7] == 'n' && literal[8] == 't' && literal[9] == 's' {
			return IMPLEMENTS
		}
	case 12:
		if literal[0] == 's' && literal[1] == 'u' && literal[2] == 'b' && literal[3] == 's' && literal[4] == 'c' && literal[5] == 'r' && literal[6] == 'i' && literal[7] == 'p' && literal[8] == 't' && literal[9] == 'i' && literal[10] == 'o' && literal[11] == 'n' {
			return SUBSCRIPTION
		}
	}

	return UNDEFINED
}
