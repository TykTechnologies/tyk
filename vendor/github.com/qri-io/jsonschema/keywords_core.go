package jsonschema

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	jptr "github.com/qri-io/jsonpointer"
)

// SchemaURI defines the $schema JSON Schema keyword
type SchemaURI string

// NewSchemaURI allocates a new SchemaURI keyword
func NewSchemaURI() Keyword {
	return new(SchemaURI)
}

// ValidateKeyword implements the Keyword interface for SchemaURI
func (s *SchemaURI) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[SchemaURI] Validating")
}

// Register implements the Keyword interface for SchemaURI
func (s *SchemaURI) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for SchemaURI
func (s *SchemaURI) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ID defines the $id JSON Schema keyword
type ID string

// NewID allocates a new Id keyword
func NewID() Keyword {
	return new(ID)
}

// ValidateKeyword implements the Keyword interface for ID
func (i *ID) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Id] Validating")
	// TODO(arqu): make sure ID is valid URI for draft2019
}

// Register implements the Keyword interface for ID
func (i *ID) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for ID
func (i *ID) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// Description defines the description JSON Schema keyword
type Description string

// NewDescription allocates a new Description keyword
func NewDescription() Keyword {
	return new(Description)
}

// ValidateKeyword implements the Keyword interface for Description
func (d *Description) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Description] Validating")
}

// Register implements the Keyword interface for Description
func (d *Description) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Description
func (d *Description) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// Title defines the title JSON Schema keyword
type Title string

// NewTitle allocates a new Title keyword
func NewTitle() Keyword {
	return new(Title)
}

// ValidateKeyword implements the Keyword interface for Title
func (t *Title) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Title] Validating")
}

// Register implements the Keyword interface for Title
func (t *Title) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Title
func (t *Title) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// Comment defines the comment JSON Schema keyword
type Comment string

// NewComment allocates a new Comment keyword
func NewComment() Keyword {
	return new(Comment)
}

// ValidateKeyword implements the Keyword interface for Comment
func (c *Comment) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Comment] Validating")
}

// Register implements the Keyword interface for Comment
func (c *Comment) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Comment
func (c *Comment) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// Default defines the default JSON Schema keyword
type Default struct {
	data interface{}
}

// NewDefault allocates a new Default keyword
func NewDefault() Keyword {
	return &Default{}
}

// ValidateKeyword implements the Keyword interface for Default
func (d *Default) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Default] Validating")
}

// Register implements the Keyword interface for Default
func (d *Default) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Default
func (d *Default) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for Default
func (d *Default) UnmarshalJSON(data []byte) error {
	var defaultData interface{}
	if err := json.Unmarshal(data, &defaultData); err != nil {
		return err
	}
	*d = Default{
		data: defaultData,
	}
	return nil
}

// Examples defines the examples JSON Schema keyword
type Examples []interface{}

// NewExamples allocates a new Examples keyword
func NewExamples() Keyword {
	return new(Examples)
}

// ValidateKeyword implements the Keyword interface for Examples
func (e *Examples) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Examples] Validating")
}

// Register implements the Keyword interface for Examples
func (e *Examples) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Examples
func (e *Examples) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ReadOnly defines the readOnly JSON Schema keyword
type ReadOnly bool

// NewReadOnly allocates a new ReadOnly keyword
func NewReadOnly() Keyword {
	return new(ReadOnly)
}

// ValidateKeyword implements the Keyword interface for ReadOnly
func (r *ReadOnly) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[ReadOnly] Validating")
}

// Register implements the Keyword interface for ReadOnly
func (r *ReadOnly) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for ReadOnly
func (r *ReadOnly) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// WriteOnly defines the writeOnly JSON Schema keyword
type WriteOnly bool

// NewWriteOnly allocates a new WriteOnly keyword
func NewWriteOnly() Keyword {
	return new(WriteOnly)
}

// ValidateKeyword implements the Keyword interface for WriteOnly
func (w *WriteOnly) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[WriteOnly] Validating")
}

// Register implements the Keyword interface for WriteOnly
func (w *WriteOnly) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for WriteOnly
func (w *WriteOnly) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// Ref defines the $ref JSON Schema keyword
type Ref struct {
	reference         string
	resolved          *Schema
	resolvedRoot      *Schema
	resolvedFragment  *jptr.Pointer
	fragmentLocalized bool
}

// NewRef allocates a new Ref keyword
func NewRef() Keyword {
	return new(Ref)
}

// ValidateKeyword implements the Keyword interface for Ref
func (r *Ref) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Ref] Validating")
	if r.resolved == nil {
		r._resolveRef(ctx, currentState)
		if r.resolved == nil {
			currentState.AddError(data, fmt.Sprintf("failed to resolve schema for ref %s", r.reference))
		}
	}

	subState := currentState.NewSubState()
	subState.ClearState()
	if r.resolvedRoot != nil {
		subState.BaseURI = r.resolvedRoot.docPath
		subState.Root = r.resolvedRoot
	}
	if r.resolvedFragment != nil && !r.resolvedFragment.IsEmpty() {
		subState.BaseRelativeLocation = r.resolvedFragment
	}
	subState.DescendRelative("$ref")

	r.resolved.ValidateKeyword(ctx, subState, data)

	currentState.UpdateEvaluatedPropsAndItems(subState)
}

// _resolveRef attempts to resolve the reference from the top-level context
func (r *Ref) _resolveRef(ctx context.Context, currentState *ValidationState) {
	if IsLocalSchemaID(r.reference) {
		r.resolved = currentState.LocalRegistry.GetLocal(r.reference)
		if r.resolved != nil {
			return
		}
	}

	docPath := currentState.BaseURI
	refParts := strings.Split(r.reference, "#")
	address := ""
	if refParts != nil && len(strings.TrimSpace(refParts[0])) > 0 {
		address = refParts[0]
	} else if docPath != "" {
		docPathParts := strings.Split(docPath, "#")
		address = docPathParts[0]
	}
	if len(refParts) > 1 {
		frag := refParts[1]
		if len(frag) > 0 && frag[0] != '/' {
			frag = "/" + frag
			r.fragmentLocalized = true
		}
		fragPointer, err := jptr.Parse(frag)
		if err != nil {
			r.resolvedFragment = &jptr.Pointer{}
		} else {
			r.resolvedFragment = &fragPointer
		}
	} else {
		r.resolvedFragment = &jptr.Pointer{}
	}

	if address != "" {
		if u, err := url.Parse(address); err == nil {
			if !u.IsAbs() {
				address = currentState.Local.id + address
				if docPath != "" {
					uriFolder := ""
					if docPath[len(docPath)-1] == '/' {
						uriFolder = docPath
					} else {
						corePath := strings.Split(docPath, "#")[0]
						pathComponents := strings.Split(corePath, "/")
						pathComponents = pathComponents[:len(pathComponents)-1]
						uriFolder = strings.Join(pathComponents, "/") + "/"
					}
					address, _ = SafeResolveURL(uriFolder, address)
				}
			}
		}
		r.resolvedRoot = GetSchemaRegistry().Get(ctx, address)
	} else {
		r.resolvedRoot = currentState.Root
	}

	if r.resolvedRoot == nil {
		return
	}

	knownSchema := GetSchemaRegistry().GetKnown(r.reference)
	if knownSchema != nil {
		r.resolved = knownSchema
		return
	}

	localURI := currentState.BaseURI
	if r.resolvedRoot != nil && r.resolvedRoot.docPath != "" {
		localURI = r.resolvedRoot.docPath
		if r.fragmentLocalized && !r.resolvedFragment.IsEmpty() {
			current := r.resolvedFragment.Head()
			sch := currentState.LocalRegistry.GetLocal("#" + *current)
			if sch != nil {
				r.resolved = sch
				return
			}
		}
	}
	r._resolveLocalRef(localURI)
}

// _resolveLocalRef attempts to resolve the reference from a local context
func (r *Ref) _resolveLocalRef(uri string) {
	if r.resolvedFragment.IsEmpty() {
		r.resolved = r.resolvedRoot
		return
	}

	if r.resolvedRoot != nil {
		r.resolved = r.resolvedRoot.Resolve(*r.resolvedFragment, uri)
	}
}

// Register implements the Keyword interface for Ref
func (r *Ref) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Ref
func (r *Ref) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for Ref
func (r *Ref) UnmarshalJSON(data []byte) error {
	var ref string
	if err := json.Unmarshal(data, &ref); err != nil {
		return err
	}
	normalizedRef, _ := url.QueryUnescape(ref)
	*r = Ref{
		reference: normalizedRef,
	}
	return nil
}

// MarshalJSON implements the json.Marshaler interface for Ref
func (r Ref) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.reference)
}

// RecursiveRef defines the $recursiveRef JSON Schema keyword
type RecursiveRef struct {
	reference        string
	resolved         *Schema
	resolvedRoot     *Schema
	resolvedFragment *jptr.Pointer

	validatingLocations map[string]bool
}

// NewRecursiveRef allocates a new RecursiveRef keyword
func NewRecursiveRef() Keyword {
	return new(RecursiveRef)
}

// ValidateKeyword implements the Keyword interface for RecursiveRef
func (r *RecursiveRef) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[RecursiveRef] Validating")
	if r.isLocationVisited(currentState.InstanceLocation.String()) {
		// recursion detected aborting further descent
		return
	}

	if r.resolved == nil {
		r._resolveRef(ctx, currentState)
		if r.resolved == nil {
			currentState.AddError(data, fmt.Sprintf("failed to resolve schema for ref %s", r.reference))
		}
	}

	subState := currentState.NewSubState()
	subState.ClearState()
	if r.resolvedRoot != nil {
		subState.BaseURI = r.resolvedRoot.docPath
		subState.Root = r.resolvedRoot
	}
	if r.resolvedFragment != nil && !r.resolvedFragment.IsEmpty() {
		subState.BaseRelativeLocation = r.resolvedFragment
	}
	subState.DescendRelative("$recursiveRef")

	if r.validatingLocations == nil {
		r.validatingLocations = map[string]bool{}
	}

	r.validatingLocations[currentState.InstanceLocation.String()] = true
	r.resolved.ValidateKeyword(ctx, subState, data)
	r.validatingLocations[currentState.InstanceLocation.String()] = false

	currentState.UpdateEvaluatedPropsAndItems(subState)
}

func (r *RecursiveRef) isLocationVisited(location string) bool {
	if r.validatingLocations == nil {
		return false
	}
	v, ok := r.validatingLocations[location]
	if !ok {
		return false
	}
	return v
}

// _resolveRef attempts to resolve the reference from the top-level context
func (r *RecursiveRef) _resolveRef(ctx context.Context, currentState *ValidationState) {
	if currentState.RecursiveAnchor != nil {
		if currentState.BaseURI == "" {
			currentState.AddError(nil, fmt.Sprintf("base uri not set"))
			return
		}
		baseSchema := GetSchemaRegistry().Get(ctx, currentState.BaseURI)
		if baseSchema != nil && baseSchema.HasKeyword("$recursiveAnchor") {
			r.resolvedRoot = currentState.RecursiveAnchor
		}
	}

	if IsLocalSchemaID(r.reference) {
		r.resolved = currentState.LocalRegistry.GetLocal(r.reference)
		if r.resolved != nil {
			return
		}
	}

	docPath := currentState.BaseURI
	if r.resolvedRoot != nil && r.resolvedRoot.docPath != "" {
		docPath = r.resolvedRoot.docPath
	}

	refParts := strings.Split(r.reference, "#")
	address := ""
	if refParts != nil && len(strings.TrimSpace(refParts[0])) > 0 {
		address = refParts[0]
	} else {
		address = docPath
	}

	if len(refParts) > 1 {

		fragPointer, err := jptr.Parse(refParts[1])
		if err != nil {
			r.resolvedFragment = &jptr.Pointer{}
		} else {
			r.resolvedFragment = &fragPointer
		}
	} else {
		r.resolvedFragment = &jptr.Pointer{}
	}

	if r.resolvedRoot == nil {
		if address != "" {
			if u, err := url.Parse(address); err == nil {
				if !u.IsAbs() {
					address = currentState.Local.id + address
					if docPath != "" {
						uriFolder := ""
						if docPath[len(docPath)-1] == '/' {
							uriFolder = docPath
						} else {
							corePath := strings.Split(docPath, "#")[0]
							pathComponents := strings.Split(corePath, "/")
							pathComponents = pathComponents[:len(pathComponents)-1]
							uriFolder = strings.Join(pathComponents, "/")
						}
						address, _ = SafeResolveURL(uriFolder, address)
					}
				}
			}
			r.resolvedRoot = GetSchemaRegistry().Get(ctx, address)
		} else {
			r.resolvedRoot = currentState.Root
		}
	}

	if r.resolvedRoot == nil {
		return
	}

	knownSchema := GetSchemaRegistry().GetKnown(r.reference)
	if knownSchema != nil {
		r.resolved = knownSchema
		return
	}

	localURI := currentState.BaseURI
	if r.resolvedRoot != nil && r.resolvedRoot.docPath != "" {
		localURI = r.resolvedRoot.docPath
	}
	r._resolveLocalRef(localURI)
}

// _resolveLocalRef attempts to resolve the reference from a local context
func (r *RecursiveRef) _resolveLocalRef(uri string) {
	if r.resolvedFragment.IsEmpty() {
		r.resolved = r.resolvedRoot
		return
	}

	if r.resolvedRoot != nil {
		r.resolved = r.resolvedRoot.Resolve(*r.resolvedFragment, uri)
	}
}

// Register implements the Keyword interface for RecursiveRef
func (r *RecursiveRef) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for RecursiveRef
func (r *RecursiveRef) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for RecursiveRef
func (r *RecursiveRef) UnmarshalJSON(data []byte) error {
	var ref string
	if err := json.Unmarshal(data, &ref); err != nil {
		return err
	}
	*r = RecursiveRef{
		reference: ref,
	}
	return nil
}

// MarshalJSON implements the json.Marshaler interface for RecursiveRef
func (r RecursiveRef) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.reference)
}

// Anchor defines the $anchor JSON Schema keyword
type Anchor string

// NewAnchor allocates a new Anchor keyword
func NewAnchor() Keyword {
	return new(Anchor)
}

// ValidateKeyword implements the Keyword interface for Anchor
func (a *Anchor) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Anchor] Validating")
}

// Register implements the Keyword interface for Anchor
func (a *Anchor) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Anchor
func (a *Anchor) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// RecursiveAnchor defines the $recursiveAnchor JSON Schema keyword
type RecursiveAnchor Schema

// NewRecursiveAnchor allocates a new RecursiveAnchor keyword
func NewRecursiveAnchor() Keyword {
	return &RecursiveAnchor{}
}

// Register implements the Keyword interface for RecursiveAnchor
func (r *RecursiveAnchor) Register(uri string, registry *SchemaRegistry) {
	(*Schema)(r).Register(uri, registry)
}

// Resolve implements the Keyword interface for RecursiveAnchor
func (r *RecursiveAnchor) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return (*Schema)(r).Resolve(pointer, uri)
}

// ValidateKeyword implements the Keyword interface for RecursiveAnchor
func (r *RecursiveAnchor) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[RecursiveAnchor] Validating")
	if currentState.RecursiveAnchor == nil {
		currentState.RecursiveAnchor = currentState.Local
	}
}

// UnmarshalJSON implements the json.Unmarshaler interface for RecursiveAnchor
func (r *RecursiveAnchor) UnmarshalJSON(data []byte) error {
	sch := &Schema{}
	if err := json.Unmarshal(data, sch); err != nil {
		return err
	}
	*r = (RecursiveAnchor)(*sch)
	return nil
}

// Defs defines the $defs JSON Schema keyword
type Defs map[string]*Schema

// NewDefs allocates a new Defs keyword
func NewDefs() Keyword {
	return &Defs{}
}

// Register implements the Keyword interface for Defs
func (d *Defs) Register(uri string, registry *SchemaRegistry) {
	for _, v := range *d {
		v.Register(uri, registry)
	}
}

// Resolve implements the Keyword interface for Defs
func (d *Defs) Resolve(pointer jptr.Pointer, uri string) *Schema {
	if pointer == nil {
		return nil
	}
	current := pointer.Head()
	if current == nil {
		return nil
	}

	if schema, ok := (*d)[*current]; ok {
		return schema.Resolve(pointer.Tail(), uri)
	}

	return nil
}

// ValidateKeyword implements the Keyword interface for Defs
func (d Defs) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Defs] Validating")
}

// JSONProp implements the JSONPather for Defs
func (d Defs) JSONProp(name string) interface{} {
	return d[name]
}

// JSONChildren implements the JSONContainer interface for Defs
func (d Defs) JSONChildren() (res map[string]JSONPather) {
	res = map[string]JSONPather{}
	for key, sch := range d {
		res[key] = sch
	}
	return
}

// Void is a placeholder definition for a keyword
type Void struct{}

// NewVoid allocates a new Void keyword
func NewVoid() Keyword {
	return &Void{}
}

// Register implements the Keyword interface for Void
func (vo *Void) Register(uri string, registry *SchemaRegistry) {}

// Resolve implements the Keyword interface for Void
func (vo *Void) Resolve(pointer jptr.Pointer, uri string) *Schema {
	return nil
}

// ValidateKeyword implements the Keyword interface for Void
func (vo *Void) ValidateKeyword(ctx context.Context, currentState *ValidationState, data interface{}) {
	schemaDebug("[Void] Validating")
	schemaDebug("[Void] WARNING this is a placeholder and should not be used")
	schemaDebug("[Void] Void is always true")
}
