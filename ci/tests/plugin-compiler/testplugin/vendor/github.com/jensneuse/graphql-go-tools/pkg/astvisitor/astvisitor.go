// Package astvisitor enables efficient and powerful traversal of GraphQL document AST's.
//
// Visitor has more options to configure the behaviour and offers more meta data than SimpleVisitor.
// SimpleVisitor on the other hand is more performant.
//
// If all Nodes should be visited and not much meta data is needed, go with SimpleVisitor.
// If you only need to visit a subset of Nodes or want specific meta data, e.g. TypeDefinitions you should go with Visitor.
package astvisitor
