package postprocess

import (
	"strconv"
	"strings"

	"github.com/jensneuse/graphql-go-tools/pkg/engine/plan"
	"github.com/jensneuse/graphql-go-tools/pkg/engine/resolve"
)

type ProcessDataSource struct{}

func (d *ProcessDataSource) Process(pre plan.Plan) plan.Plan {
	switch t := pre.(type) {
	case *plan.SynchronousResponsePlan:
		d.traverseNode(t.Response.Data)
	case *plan.StreamingResponsePlan:
		d.traverseNode(t.Response.InitialResponse.Data)
		for i := range t.Response.Patches {
			d.traverseFetch(t.Response.Patches[i].Fetch)
			d.traverseNode(t.Response.Patches[i].Value)
		}
	case *plan.SubscriptionResponsePlan:
		d.traverseTrigger(&t.Response.Trigger)
		d.traverseNode(t.Response.Response.Data)
	}
	return pre
}

func (d *ProcessDataSource) traverseNode(node resolve.Node) {
	switch n := node.(type) {
	case *resolve.Object:
		d.traverseFetch(n.Fetch)
		for i := range n.Fields {
			d.traverseNode(n.Fields[i].Value)
		}
	case *resolve.Array:
		d.traverseNode(n.Item)
	}
}

func (d *ProcessDataSource) traverseFetch(fetch resolve.Fetch) {
	if fetch == nil {
		return
	}
	switch f := fetch.(type) {
	case *resolve.SingleFetch:
		d.traverseSingleFetch(f)
	case *resolve.ParallelFetch:
		for i := range f.Fetches {
			d.traverseSingleFetch(f.Fetches[i])
		}
	}
}

func (d *ProcessDataSource) traverseTrigger(trigger *resolve.GraphQLSubscriptionTrigger) {
	defer func() {
		trigger.Variables = nil
		trigger.Input = ""
	}()

	if trigger.Input == "" {
		return
	}

	if !strings.Contains(trigger.Input, "$$") {
		trigger.InputTemplate.Segments = append(trigger.InputTemplate.Segments, resolve.TemplateSegment{
			SegmentType: resolve.StaticSegmentType,
			Data:        []byte(trigger.Input),
		})
		return
	}

	segments := strings.Split(trigger.Input, "$$")

	isVariable := false
	for _, seg := range segments {
		switch {
		case isVariable:
			i, _ := strconv.Atoi(seg)
			switch v := (trigger.Variables)[i].(type) {
			case *resolve.ContextVariable:
				trigger.InputTemplate.Segments = append(trigger.InputTemplate.Segments, resolve.TemplateSegment{
					SegmentType:        resolve.VariableSegmentType,
					VariableSource:     resolve.VariableSourceContext,
					VariableSourcePath: v.Path,
				})
			case *resolve.ObjectVariable:
				trigger.InputTemplate.Segments = append(trigger.InputTemplate.Segments, resolve.TemplateSegment{
					SegmentType:        resolve.VariableSegmentType,
					VariableSource:     resolve.VariableSourceObject,
					VariableSourcePath: v.Path,
				})
			}
			isVariable = false
		default:
			trigger.InputTemplate.Segments = append(trigger.InputTemplate.Segments, resolve.TemplateSegment{
				SegmentType: resolve.StaticSegmentType,
				Data:        []byte(seg),
			})
			isVariable = true
		}
	}
}

func (d *ProcessDataSource) traverseSingleFetch(fetch *resolve.SingleFetch) {
	defer func() {
		fetch.Variables = nil
		fetch.Input = ""
	}()

	if fetch.Input == "" {
		return
	}

	if !strings.Contains(fetch.Input, "$$") {
		fetch.InputTemplate.Segments = append(fetch.InputTemplate.Segments, resolve.TemplateSegment{
			SegmentType: resolve.StaticSegmentType,
			Data:        []byte(fetch.Input),
		})
		return
	}

	segments := strings.Split(fetch.Input, "$$")

	isVariable := false
	for _, seg := range segments {
		switch {
		case isVariable:
			i, _ := strconv.Atoi(seg)
			switch v := (fetch.Variables)[i].(type) {
			case *resolve.ContextVariable:
				fetch.InputTemplate.Segments = append(fetch.InputTemplate.Segments, resolve.TemplateSegment{
					SegmentType:        resolve.VariableSegmentType,
					VariableSource:     resolve.VariableSourceContext,
					VariableSourcePath: v.Path,
				})
			case *resolve.ObjectVariable:
				fetch.InputTemplate.Segments = append(fetch.InputTemplate.Segments, resolve.TemplateSegment{
					SegmentType:        resolve.VariableSegmentType,
					VariableSource:     resolve.VariableSourceObject,
					VariableSourcePath: v.Path,
				})
			}
			isVariable = false
		default:
			fetch.InputTemplate.Segments = append(fetch.InputTemplate.Segments, resolve.TemplateSegment{
				SegmentType: resolve.StaticSegmentType,
				Data:        []byte(seg),
			})
			isVariable = true
		}
	}
}
