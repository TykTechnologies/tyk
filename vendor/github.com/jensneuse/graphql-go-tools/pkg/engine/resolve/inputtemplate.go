package resolve

import (
	"context"
	"fmt"
	"net/textproto"

	"github.com/buger/jsonparser"
	"github.com/jensneuse/graphql-go-tools/pkg/fastbuffer"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type SegmentType int

const (
	StaticSegmentType SegmentType = iota + 1
	VariableSegmentType
)

type TemplateSegment struct {
	SegmentType        SegmentType
	Data               []byte
	VariableKind       VariableKind
	VariableSourcePath []string
	Renderer           VariableRenderer
}

type InputTemplate struct {
	Segments []TemplateSegment
}

func (i *InputTemplate) Render(ctx *Context, data []byte, preparedInput *fastbuffer.FastBuffer) (err error) {
	for j := range i.Segments {
		switch i.Segments[j].SegmentType {
		case StaticSegmentType:
			preparedInput.WriteBytes(i.Segments[j].Data)
		case VariableSegmentType:
			switch i.Segments[j].VariableKind {
			case ObjectVariableKind:
				err = i.renderObjectVariable(ctx, data, i.Segments[j], preparedInput)
			case ContextVariableKind:
				err = i.renderContextVariable(ctx, i.Segments[j], preparedInput)
			case HeaderVariableKind:
				err = i.renderHeaderVariable(ctx, i.Segments[j].VariableSourcePath, preparedInput)
			default:
				err = fmt.Errorf("InputTemplate.Render: cannot resolve variable of kind: %d", i.Segments[j].VariableKind)
			}
			if err != nil {
				return err
			}
		}
	}
	return
}

func (i *InputTemplate) renderObjectVariable(ctx context.Context, variables []byte, segment TemplateSegment, preparedInput *fastbuffer.FastBuffer) error {
	value, valueType, offset, err := jsonparser.Get(variables, segment.VariableSourcePath...)
	if err != nil || valueType == jsonparser.Null {
		preparedInput.WriteBytes(literal.NULL)
		return nil
	}
	if valueType == jsonparser.String {
		value = variables[offset-len(value)-2:offset]
	}
	return segment.Renderer.RenderVariable(ctx, value, preparedInput)
}

func (i *InputTemplate) renderContextVariable(ctx *Context, segment TemplateSegment, preparedInput *fastbuffer.FastBuffer) error {
	value, valueType, offset, err := jsonparser.Get(ctx.Variables, segment.VariableSourcePath...)
	if err != nil || valueType == jsonparser.Null {
		preparedInput.WriteBytes(literal.NULL)
		return nil
	}
	if valueType == jsonparser.String {
		value = ctx.Variables[offset-len(value)-2:offset]
	}
	return segment.Renderer.RenderVariable(ctx, value, preparedInput)
}

func (i *InputTemplate) renderHeaderVariable(ctx *Context, path []string, preparedInput *fastbuffer.FastBuffer) error {
	if len(path) != 1 {
		return errHeaderPathInvalid
	}
	// Header.Values is available from go 1.14
	// value := ctx.Request.Header.Values(path[0])
	// could be simplified once go 1.12 support will be dropped
	canonicalName := textproto.CanonicalMIMEHeaderKey(path[0])
	value := ctx.Request.Header[canonicalName]
	if len(value) == 0 {
		return nil
	}
	if len(value) == 1 {
		preparedInput.WriteString(value[0])
		return nil
	}
	for j := range value {
		if j != 0 {
			preparedInput.WriteBytes(literal.COMMA)
		}
		preparedInput.WriteString(value[j])
	}
	return nil
}
