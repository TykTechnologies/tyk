/*Package astnormalization helps to transform parsed GraphQL AST's into a easier to use structure.

Example

This examples shows how the normalization package helps "simplifying" a GraphQL AST.

Input:

 subscription sub {
 	... multipleSubscriptions
	... on Subscription {
		newMessage {
			body
			sender
		}
	}
 }
 fragment newMessageFields on Message {
 	body: body
 	sender
 	... on Body {
 		body
 	}
 }
 fragment multipleSubscriptions on Subscription {
 	newMessage {
 		body
 		sender
 	}
 	newMessage {
 		... newMessageFields
 	}
 	newMessage {
 		body
 		body
		sender
 	}
 	... on Subscription {
 		newMessage {
 			body
 			sender
 		}
 	}
 	disallowedSecondRootField
 }

Output:

 subscription sub {
 	newMessage {
 		body
 		sender
 	}
 	disallowedSecondRootField
 }
 fragment newMessageFields on Message {
 	body
 	sender
 }
 fragment multipleSubscriptions on Subscription {
 	newMessage {
 		body
 		sender
 	}
 	disallowedSecondRootField
 }
*/
package astnormalization

import (
	"github.com/jensneuse/graphql-go-tools/pkg/ast"
	"github.com/jensneuse/graphql-go-tools/pkg/astvisitor"
	"github.com/jensneuse/graphql-go-tools/pkg/operationreport"
)

// NormalizeOperation creates a default Normalizer and applies all rules to a given AST
// In case you're using OperationNormalizer in a hot path you shouldn't be using this function.
// Create a new OperationNormalizer using NewNormalizer() instead and re-use it.
func NormalizeOperation(operation, definition *ast.Document, report *operationreport.Report) {
	normalizer := NewNormalizer(false, false)
	normalizer.NormalizeOperation(operation, definition, report)
}

func NormalizeNamedOperation(operation, definition *ast.Document, operationName []byte, report *operationreport.Report) {
	normalizer := NewNormalizer(true, true)
	normalizer.NormalizeNamedOperation(operation, definition, operationName, report)
}

type registerNormalizeFunc func(walker *astvisitor.Walker)

type registerNormalizeVariablesFunc func(walker *astvisitor.Walker) *variablesExtractionVisitor

// OperationNormalizer walks a given AST and applies all registered rules
type OperationNormalizer struct {
	walkers                   []*astvisitor.Walker
	removeFragmentDefinitions bool
	extractVariables          bool
	variablesExtraction       *variablesExtractionVisitor
}

// NewNormalizer creates a new OperationNormalizer and sets up all default rules
func NewNormalizer(removeFragmentDefinitions, extractVariables bool) *OperationNormalizer {
	normalizer := &OperationNormalizer{
		removeFragmentDefinitions: removeFragmentDefinitions,
		extractVariables:          extractVariables,
	}
	normalizer.setupWalkers()
	return normalizer
}

func (o *OperationNormalizer) setupWalkers() {
	fragmentInline := astvisitor.NewWalker(48)
	fragmentSpreadInline(&fragmentInline)
	directiveIncludeSkip(&fragmentInline)

	other := astvisitor.NewWalker(48)
	removeSelfAliasing(&other)
	mergeInlineFragments(&other)
	mergeFieldSelections(&other)
	deduplicateFields(&other)
	if o.extractVariables {
		o.variablesExtraction = extractVariables(&other)
	}
	if o.removeFragmentDefinitions {
		removeFragmentDefinitions(&other)
	}

	o.walkers = append(o.walkers, &fragmentInline, &other)
}

// NormalizeOperation applies all registered rules to the AST
func (o *OperationNormalizer) NormalizeOperation(operation, definition *ast.Document, report *operationreport.Report) {
	for i := range o.walkers {
		o.walkers[i].Walk(operation, definition, report)
		if report.HasErrors() {
			return
		}
	}
}

// NormalizeNamedOperation applies all registered rules to one specific named operation in the AST
func (o *OperationNormalizer) NormalizeNamedOperation(operation, definition *ast.Document, operationName []byte, report *operationreport.Report) {
	if o.variablesExtraction != nil {
		o.variablesExtraction.operationName = operationName
	}
	for i := range o.walkers {
		o.walkers[i].Walk(operation, definition, report)
		if report.HasErrors() {
			return
		}
	}
}
