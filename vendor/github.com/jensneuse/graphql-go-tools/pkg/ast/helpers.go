package ast

// indexOf - simple helper to find an index of a ref within refs slice
func indexOf(refs []int, ref int) (int, bool) {
	for i, j := range refs {
		if ref == j {
			return i, true
		}
	}
	return -1, false
}

// deleteRef - is a slice trick to remove an item with preserving items order
// Note: danger modifies pointer to the arr
func deleteRef(refs *[]int, index int) {
	*refs = append((*refs)[:index], (*refs)[index+1:]...)
}
