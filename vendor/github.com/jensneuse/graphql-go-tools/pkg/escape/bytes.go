package escape

func Bytes(in, out []byte) []byte {

	out = out[:0]

	for i := range in {

		switch in[i] {
		case 9:
			out = append(out, 92, 116) // \t
		case 10:
			out = append(out, 92, 110) // \n
		case 34:
			if i > 0 && in[i-1] == 92 {
				out = append(out, 92, 92, 34) // \\"
			} else {
				out = append(out, 92, 34) // \"
			}
		default:
			out = append(out, in[i])
		}
	}

	return out
}
