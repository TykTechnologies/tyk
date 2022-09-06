package quotes

const (
	quoteStr = "\""
)

var (
	quoteBytes = []byte(quoteStr)
)

func WrapBytes(bytes []byte) []byte {
	cp := make([]byte, len(bytes))
	copy(cp, bytes)
	return append(quoteBytes, append(cp, quoteBytes...)...)
}

func WrapString(str string) string {
	return quoteStr + str + quoteStr
}
