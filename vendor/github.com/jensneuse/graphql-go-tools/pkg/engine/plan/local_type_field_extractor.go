package plan

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
)

const (
	federationKeyDirectiveName      = "key"
	federationRequireDirectiveName  = "requires"
	federationExternalDirectiveName = "external"
)

// LocalTypeFieldExtractor takes an ast.Document as input and generates the
// TypeField configuration for both root and child nodes. Root nodes are the
// root operation types (usually Query, Mutation and Schema--though these types
// can be configured via the schema keyword) plus "entities" as defined by the
// Apollo federation specification. In short, entities are types with a @key
// directive. Child nodes are field types recursively accessible via a root
// node. Nodes are either object or interface definitions or extensions. Root
// nodes only include "local" fields; they don't include fields that have the
// @external directive.
type LocalTypeFieldExtractor struct {
	document               *ast.Document
	queryTypeName          string
	mutationTypeName       string
	subscriptionTypeName   string
	nodeInfoMap            map[string]*nodeInformation
	possibleInterfaceTypes map[string][]string
	rootNodeNames          *rootNodeNamesMap
	childrenSeen           map[string]struct{}
	childrenToProcess      []string
	rootNodes              []TypeField
	childNodes             []TypeField
}

func NewLocalTypeFieldExtractor(document *ast.Document) *LocalTypeFieldExtractor {
	return &LocalTypeFieldExtractor{
		document:             document,
		queryTypeName:        "Query",
		mutationTypeName:     "Mutation",
		subscriptionTypeName: "Subscription",
		rootNodes:            make([]TypeField, 0),
		childNodes:           make([]TypeField, 0),
	}
}

type nodeInformation struct {
	typeName          string
	hasKeyDirective   bool
	isInterface       bool
	isRoot            bool
	concreteTypeNames []string
	localFieldRefs    []int
	externalFieldRefs []int
}

type rootNodeNamesMap struct {
	index int
	names map[string]int
}

func newRootNodeNamesMap() *rootNodeNamesMap {
	return &rootNodeNamesMap{
		index: 0,
		names: map[string]int{},
	}
}

func (r *rootNodeNamesMap) append(name string) {
	if _, ok := r.names[name]; ok {
		return
	}

	r.names[name] = r.index
	r.index++
}

func (r *rootNodeNamesMap) asSlice() []string {
	s := make([]string, len(r.names))
	for name, i := range r.names {
		s[i] = name
	}

	return s
}

// GetAllNodes returns all root and child nodes in the document associated with
// the LocalTypeFieldExtractor. See LocalTypeFieldExtractor for a detailed
// explanation of what root and child nodes are.
func (e *LocalTypeFieldExtractor) GetAllNodes() ([]TypeField, []TypeField) {
	// The strategy for the extractor is as follows:
	//
	// 1. Loop over each node in the document and collect information into
	//    "node info" structs. All document nodes are processed before creating
	//    the final "root" and "child" plan nodes because multiple document
	//    nodes may correspond to a single "node info" struct. For example,
	//    `type User { ... }` and `extend type User { ... }` nodes will
	//    correspond to a single User struct.
	//
	// 2. Build root nodes for each node info struct identified as a root node.
	//
	// 3. Push the root node info structs into a queue and construct a child
	//    node for each info struct in the queue. After constructing a child
	//    node, loop over the fields of the child type and add any object or
	//    abstract type to the queue if the type hasn't yet been processed. An
	//    abstract type is either an interface or union. When processing
	//    abstract types, also add the corresponding concrete types to the
	//    queue (i.e. all the types that implement an interface and union
	//    members). Note that child nodes aren't created for union types--only
	//    union members--since it ISN'T possible to select directly from a
	//    union; union selection sets MUST contain fragments.

	e.nodeInfoMap = make(map[string]*nodeInformation, len(e.document.RootNodes))
	e.possibleInterfaceTypes = map[string][]string{}
	e.rootNodeNames = newRootNodeNamesMap()
	e.overrideRootOperationTypeNames()

	// 1. Loop over each node in the document (see description above).
	e.collectNodeInformation()

	// Record the concrete types for each interface.
	e.assignConcreteTypesToInterfaces()

	// Make sure that root and child node slices are cleared
	e.resetRootAndChildNodes()

	// 2. Create the root nodes. Also, loop over the fields to find additional
	// child nodes to process.
	e.createRootNodes()

	// 3. Process the child node queue to create child nodes. When processing
	// child nodes, loop over the fields of the child to find additional
	// children to process.
	e.createChildNodes()

	return e.rootNodes, e.childNodes
}

func (e *LocalTypeFieldExtractor) overrideRootOperationTypeNames() {
	indexedQueryTypeName := string(e.document.Index.QueryTypeName)
	if indexedQueryTypeName != "" && indexedQueryTypeName != e.queryTypeName {
		e.queryTypeName = indexedQueryTypeName
	}

	indexedMutationTypeName := string(e.document.Index.MutationTypeName)
	if indexedMutationTypeName != "" && indexedMutationTypeName != e.mutationTypeName {
		e.mutationTypeName = indexedMutationTypeName
	}

	indexedSubscriptionTypeName := string(e.document.Index.SubscriptionTypeName)
	if indexedSubscriptionTypeName != "" && indexedSubscriptionTypeName != e.subscriptionTypeName {
		e.subscriptionTypeName = indexedSubscriptionTypeName
	}
}

func (e *LocalTypeFieldExtractor) collectNodeInformation() {
	for _, astNode := range e.document.RootNodes {
		nodeInfo := e.getNodeInfo(astNode)

		switch astNode.Kind {
		case ast.NodeKindObjectTypeDefinition, ast.NodeKindObjectTypeExtension:
			for _, ref := range e.document.NodeInterfaceRefs(astNode) {
				interfaceName := e.document.ResolveTypeNameString(ref)
				// The document doesn't provide a way to directly look up the
				// types that implement an interface, so instead we track the
				// interfaces implemented for each type and after all nodes
				// have been processed record the concrete types for each
				// interface.
				e.possibleInterfaceTypes[interfaceName] = append(
					e.possibleInterfaceTypes[interfaceName], nodeInfo.typeName)
			}
		case ast.NodeKindInterfaceTypeDefinition, ast.NodeKindInterfaceTypeExtension:
			nodeInfo.isInterface = true
		case ast.NodeKindUnionTypeDefinition, ast.NodeKindUnionTypeExtension:
			for _, ref := range e.document.NodeUnionMemberRefs(astNode) {
				// Local union extensions are disjoint. For details, see the GraphQL
				// spec: https://spec.graphql.org/October2021/#sec-Union-Extensions
				memberName := e.document.ResolveTypeNameString(ref)
				nodeInfo.concreteTypeNames = append(nodeInfo.concreteTypeNames, memberName)
			}
		default:
			continue
		}

		nodeInfo.isRoot = nodeInfo.isRoot || e.isRootNode(nodeInfo)
		if nodeInfo.isRoot {
			e.rootNodeNames.append(nodeInfo.typeName)
		}

		// Record the local and external fields separately for later
		// processing. Root nodes only include local fields, while child nodes
		// include both local and external fields.
		e.collectFieldDefinitions(astNode, nodeInfo)
	}
}

func (e *LocalTypeFieldExtractor) getNodeInfo(node ast.Node) *nodeInformation {
	typeName := e.document.NodeNameString(node)
	nodeInfo, ok := e.nodeInfoMap[typeName]
	if ok {
		// if this node has the key directive, we need to add it to the node information
		nodeInfo.hasKeyDirective = nodeInfo.hasKeyDirective || e.document.NodeHasDirectiveByNameString(node, federationKeyDirectiveName)
		return nodeInfo
	}

	nodeInfo = &nodeInformation{
		typeName:        typeName,
		hasKeyDirective: e.document.NodeHasDirectiveByNameString(node, federationKeyDirectiveName),
	}

	e.nodeInfoMap[typeName] = nodeInfo
	return nodeInfo
}

func (e *LocalTypeFieldExtractor) isRootNode(nodeInfo *nodeInformation) bool {
	isFederationEntity := nodeInfo.hasKeyDirective && !nodeInfo.isInterface
	return nodeInfo.typeName == e.queryTypeName ||
		nodeInfo.typeName == e.mutationTypeName ||
		nodeInfo.typeName == e.subscriptionTypeName ||
		isFederationEntity
}

func (e *LocalTypeFieldExtractor) collectFieldDefinitions(node ast.Node, nodeInfo *nodeInformation) {
	for _, ref := range e.document.NodeFieldDefinitions(node) {
		isExternal := e.document.FieldDefinitionHasNamedDirective(ref,
			federationExternalDirectiveName)

		if isExternal {
			nodeInfo.externalFieldRefs = append(nodeInfo.externalFieldRefs, ref)
		} else {
			nodeInfo.localFieldRefs = append(nodeInfo.localFieldRefs, ref)
		}
	}
}

func (e *LocalTypeFieldExtractor) assignConcreteTypesToInterfaces() {
	for interfaceName, concreteTypeNames := range e.possibleInterfaceTypes {
		if nodeInfo, ok := e.nodeInfoMap[interfaceName]; ok {
			nodeInfo.concreteTypeNames = concreteTypeNames
		}
	}
}

// pushChildIfNotAlreadyProcessed pushes a child type onto the queue if it
// hasn't already been processed. Only types with node info are pushed onto
// the queue. Recall that node info is limited to object types, interfaces
// and union members above.
func (e *LocalTypeFieldExtractor) pushChildIfNotAlreadyProcessed(typeName string) {
	if _, ok := e.childrenSeen[typeName]; !ok {
		if _, ok := e.nodeInfoMap[typeName]; ok {
			e.childrenToProcess = append(e.childrenToProcess, typeName)
		}
		e.childrenSeen[typeName] = struct{}{}
	}
}

// processFieldRef pushes node info for the field's type as well as--in the
// case of abstract types--node info for each concrete type.
func (e *LocalTypeFieldExtractor) processFieldRef(ref int) string {
	fieldType := e.document.FieldDefinitionType(ref)
	fieldTypeName := e.document.ResolveTypeNameString(fieldType)
	e.pushChildIfNotAlreadyProcessed(fieldTypeName)
	if nodeInfo, ok := e.nodeInfoMap[fieldTypeName]; ok {
		for _, name := range nodeInfo.concreteTypeNames {
			e.pushChildIfNotAlreadyProcessed(name)
		}
	}
	return e.document.FieldDefinitionNameString(ref)
}

func (e *LocalTypeFieldExtractor) resetRootAndChildNodes() {
	e.rootNodes = e.rootNodes[:0]
	e.childNodes = e.childNodes[:0]

	// This is the queue used in step 3, child node construction.
	e.childrenSeen = make(map[string]struct{}, len(e.nodeInfoMap))
	e.childrenToProcess = make([]string, 0, len(e.nodeInfoMap))
}

func (e *LocalTypeFieldExtractor) createRootNodes() {
	for _, typeName := range e.rootNodeNames.asSlice() {
		nodeInfo := e.nodeInfoMap[typeName]
		numFields := len(nodeInfo.localFieldRefs)
		if numFields == 0 {
			continue
		}
		fieldNames := make([]string, numFields)
		for i, ref := range nodeInfo.localFieldRefs {
			fieldNames[i] = e.processFieldRef(ref)
		}
		e.rootNodes = append(e.rootNodes, TypeField{
			TypeName:   typeName,
			FieldNames: fieldNames,
		})
	}
}

func (e *LocalTypeFieldExtractor) createChildNodes() {
	for len(e.childrenToProcess) > 0 {
		typeName := e.childrenToProcess[len(e.childrenToProcess)-1]
		e.childrenToProcess = e.childrenToProcess[:len(e.childrenToProcess)-1]
		nodeInfo, ok := e.nodeInfoMap[typeName]
		if !ok {
			continue
		}
		numFields := len(nodeInfo.localFieldRefs) + len(nodeInfo.externalFieldRefs)
		if numFields == 0 {
			continue
		}
		fieldNames := make([]string, 0, numFields)
		for _, ref := range nodeInfo.localFieldRefs {
			fieldNames = append(fieldNames, e.processFieldRef(ref))
		}
		for _, ref := range nodeInfo.externalFieldRefs {
			fieldNames = append(fieldNames, e.processFieldRef(ref))
		}
		e.childNodes = append(e.childNodes, TypeField{
			TypeName:   typeName,
			FieldNames: fieldNames,
		})
	}
}
