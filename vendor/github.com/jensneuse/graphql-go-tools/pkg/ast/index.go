package ast

// Index is a struct to easily look up objects in a document, e.g. find Nodes (type/interface/union definitions) by name
type Index struct {
	// QueryTypeName is the name of the query type on the schema Node
	// schema { query: Query }
	QueryTypeName ByteSlice
	// MutationTypeName is the name of the mutation type on the schema Node
	// schema { mutation: Mutation }
	MutationTypeName ByteSlice
	// SubscriptionTypeName is the name of the subscription type on the schema Node
	// schema { subscription: Subscription }
	SubscriptionTypeName ByteSlice
	// Nodes is a list of all root nodes in a schema definition
	// The map key is the result of the xxhash algorithm from the Node name.
	Nodes map[uint64]Node
	// ReplacedFragmentSpreads is a list of references (slice indices) of all FragmentSpreads that got replaced during normalization.
	ReplacedFragmentSpreads []int
	// MergedTypeExtensions is a list of Nodes (Node kind + reference) that got merged during type extension merging.
	MergedTypeExtensions []Node
}

// Reset empties the Index
func (i *Index) Reset() {
	i.QueryTypeName = i.QueryTypeName[:0]
	i.MutationTypeName = i.MutationTypeName[:0]
	i.SubscriptionTypeName = i.SubscriptionTypeName[:0]
	i.ReplacedFragmentSpreads = i.ReplacedFragmentSpreads[:0]
	i.MergedTypeExtensions = i.MergedTypeExtensions[:0]
	for j := range i.Nodes {
		delete(i.Nodes, j)
	}
}
