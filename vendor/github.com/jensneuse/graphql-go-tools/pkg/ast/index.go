package ast

import (
	"bytes"

	"github.com/cespare/xxhash"
)

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
	// nodes is a list of all root nodes in a schema definition
	// The map key is the result of the xxhash algorithm from the Node name.
	nodes map[uint64][]Node
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
	for j := range i.nodes {
		delete(i.nodes, j)
	}
}

func (i *Index) AddNodeStr(name string, node Node) {
	hash := xxhash.Sum64String(name)
	_, exists := i.nodes[hash]
	if !exists {
		i.nodes[hash] = []Node{node}
		return
	}
	i.nodes[hash] = append(i.nodes[hash], node)
}

func (i *Index) AddNodeBytes(name []byte, node Node) {
	hash := xxhash.Sum64(name)
	_, exists := i.nodes[hash]
	if !exists {
		i.nodes[hash] = []Node{node}
		return
	}
	i.nodes[hash] = append(i.nodes[hash], node)
}

func (i *Index) NodesByNameStr(name string) ([]Node, bool) {
	hash := xxhash.Sum64String(name)
	node, exists := i.nodes[hash]
	return node, exists
}

func (i *Index) FirstNodeByNameStr(name string) (Node, bool) {
	hash := xxhash.Sum64String(name)
	node, exists := i.nodes[hash]
	if !exists || len(node) == 0 {
		return Node{}, false
	}
	return node[0], true
}

func (i *Index) NodesByNameBytes(name []byte) ([]Node, bool) {
	hash := xxhash.Sum64(name)
	node, exists := i.nodes[hash]
	return node, exists
}

func (i *Index) FirstNodeByNameBytes(name []byte) (Node, bool) {
	hash := xxhash.Sum64(name)
	node, exists := i.nodes[hash]
	if !exists || len(node) == 0 {
		return Node{}, false
	}
	return node[0], true
}

func (i *Index) RemoveNodeByName(name []byte) {
	hash := xxhash.Sum64(name)
	delete(i.nodes, hash)

	if bytes.Equal(i.QueryTypeName, name) {
		i.QueryTypeName = nil
	}

	if bytes.Equal(i.MutationTypeName, name) {
		i.MutationTypeName = nil
	}

	if bytes.Equal(i.SubscriptionTypeName, name) {
		i.SubscriptionTypeName = nil
	}
}
