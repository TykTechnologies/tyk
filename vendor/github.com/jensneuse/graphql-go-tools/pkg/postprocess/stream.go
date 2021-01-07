package postprocess

import (
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type ProcessStream struct {
	out       *plan.StreamingResponsePlan
	didUpdate bool
}

func (p *ProcessStream) Process(pre plan.Plan) plan.Plan {

	p.out = nil
	p.didUpdate = false

	switch in := pre.(type) {
	case *plan.SynchronousResponsePlan:
		return p.processSynchronousPlan(in)
	case *plan.StreamingResponsePlan:
		return p.processStreamingResponsePlan(in)
	default:
		return pre
	}
}

func (p *ProcessStream) processStreamingResponsePlan(in *plan.StreamingResponsePlan) plan.Plan {
	p.out = in
	for i := range p.out.Response.Patches {
		p.traverseNode(p.out.Response.Patches[i].Value)
	}
	p.traverseNode(p.out.Response.InitialResponse.Data)
	return p.out
}

func (p *ProcessStream) processSynchronousPlan(in *plan.SynchronousResponsePlan) plan.Plan {
	p.out = &plan.StreamingResponsePlan{
		FlushInterval: in.FlushInterval,
		Response: resolve.GraphQLStreamingResponse{
			InitialResponse: in.Response,
			FlushInterval:   in.FlushInterval,
		},
	}
	p.traverseNode(in.Response.Data)
	if p.didUpdate {
		return p.out
	}
	return in
}

func (p *ProcessStream) traverseNode(node resolve.Node) {
	switch n := node.(type) {
	case *resolve.Object:
		for i := range n.Fields {
			if n.Fields[i].Stream != nil {
				switch array := n.Fields[i].Value.(type) {
				case *resolve.Array:
					array.Stream.Enabled = true
					array.Stream.InitialBatchSize = n.Fields[i].Stream.InitialBatchSize
					n.Fields[i].Stream = nil
				}
			}
			p.traverseNode(n.Fields[i].Value)
		}
	case *resolve.Array:
		if n.Stream.Enabled {
			p.didUpdate = true
			patch := &resolve.GraphQLResponsePatch{
				Value:     n.Item,
				Operation: literal.ADD,
			}
			if n.Stream.InitialBatchSize == 0 {
				n.Item = nil
			}
			p.out.Response.Patches = append(p.out.Response.Patches, patch)
			n.Stream.PatchIndex = len(p.out.Response.Patches) - 1

			p.traverseNode(p.out.Response.Patches[n.Stream.PatchIndex].Value)

			return
		}
		p.traverseNode(n.Item)
	}
}
