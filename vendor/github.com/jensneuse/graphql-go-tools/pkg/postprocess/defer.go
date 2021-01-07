package postprocess

import (
	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
	"github.com/jensneuse/graphql-go-tools/pkg/lexer/literal"
)

type ProcessDefer struct {
	objects []*resolve.Object
	out     *plan.StreamingResponsePlan
	updated bool
}

func (p *ProcessDefer) Process(pre plan.Plan) plan.Plan {

	p.out = nil
	p.updated = false
	p.objects = p.objects[:0]

	switch in := pre.(type) {
	case *plan.SynchronousResponsePlan:
		return p.synchronousResponse(in)
	case *plan.StreamingResponsePlan:
		return p.processStreamingResponsePlan(in)
	default:
		return pre
	}
}

func (p *ProcessDefer) processStreamingResponsePlan(in *plan.StreamingResponsePlan) plan.Plan {
	p.out = in
	for i := range p.out.Response.Patches {
		p.traverseNode(p.out.Response.Patches[i].Value)
	}
	p.traverseNode(p.out.Response.InitialResponse.Data)
	return p.out
}

func (p *ProcessDefer) synchronousResponse(pre *plan.SynchronousResponsePlan) plan.Plan {
	p.out = &plan.StreamingResponsePlan{
		FlushInterval: pre.FlushInterval,
		Response: resolve.GraphQLStreamingResponse{
			InitialResponse: pre.Response,
			FlushInterval:   pre.FlushInterval,
		},
	}
	p.traverseNode(p.out.Response.InitialResponse.Data)
	if p.updated {
		return p.out
	}
	return pre
}

func (p *ProcessDefer) traverseNode(node resolve.Node) {

	switch n := node.(type) {
	case *resolve.Object:
		p.objects = append(p.objects, n)
		for i := range n.Fields {
			if n.Fields[i].Defer != nil {
				p.updated = true
				patchIndex, ok := p.createPatch(n, i)
				if !ok {
					continue
				}
				n.Fields[i].Defer = nil
				n.Fields[i].Value = &resolve.Null{
					Defer: resolve.Defer{
						Enabled:    true,
						PatchIndex: patchIndex,
					},
				}
				p.traverseNode(p.out.Response.Patches[patchIndex].Value)
			} else {
				p.traverseNode(n.Fields[i].Value)
			}
		}
		p.objects = p.objects[:len(p.objects)-1]
	case *resolve.Array:
		p.traverseNode(n.Item)
	}
}

func (p *ProcessDefer) createPatch(object *resolve.Object, field int) (int, bool) {
	oldValue := object.Fields[field].Value
	var patch *resolve.GraphQLResponsePatch
	if object.Fields[field].HasBuffer && !p.bufferUsedOnNonDeferField(object, field, object.Fields[field].BufferID) {
		patchFetch, ok := p.processFieldSetBuffer(object, field)
		if !ok {
			return 0, false
		}
		patch = &resolve.GraphQLResponsePatch{
			Value:     oldValue,
			Fetch:     &patchFetch,
			Operation: literal.REPLACE,
		}
		object.Fields[field].HasBuffer = false
		object.Fields[field].BufferID = 0
	} else {
		patch = &resolve.GraphQLResponsePatch{
			Value:     oldValue,
			Operation: literal.REPLACE,
		}
	}
	p.out.Response.Patches = append(p.out.Response.Patches, patch)
	patchIndex := len(p.out.Response.Patches) - 1
	return patchIndex, true
}

func (p *ProcessDefer) bufferUsedOnNonDeferField(object *resolve.Object, field, bufferID int) bool {
	for i := range object.Fields {
		if object.Fields[i].BufferID != bufferID {
			continue
		}
		if i == field {
			continue // skip currently evaluated field
		}
		if object.Fields[i].Defer == nil {
			return true
		}
	}
	return false
}

func (p *ProcessDefer) processFieldSetBuffer(object *resolve.Object, field int) (patchFetch resolve.SingleFetch, ok bool) {
	id := object.Fields[field].BufferID
	if p.objects[len(p.objects)-1].Fetch == nil {
		return patchFetch, false
	}
	switch fetch := p.objects[len(p.objects)-1].Fetch.(type) {
	case *resolve.SingleFetch:
		if fetch.BufferId != id {
			return patchFetch, false
		}
		patchFetch = *fetch
		patchFetch.BufferId = 0
		p.objects[len(p.objects)-1].Fetch = nil
		return patchFetch, true
	case *resolve.ParallelFetch:
		for k := range fetch.Fetches {
			if id == fetch.Fetches[k].BufferId {
				patchFetch = *fetch.Fetches[k]
				patchFetch.BufferId = 0
				fetch.Fetches = append(fetch.Fetches[:k], fetch.Fetches[k+1:]...)
				if len(fetch.Fetches) == 1 {
					p.objects[len(p.objects)-1].Fetch = fetch.Fetches[0]
				}
				return patchFetch, true
			}
		}
	}
	return patchFetch, false
}
