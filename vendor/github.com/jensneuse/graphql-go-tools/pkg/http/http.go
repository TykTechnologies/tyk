// Package http handles GraphQL HTTP Requests including WebSocket Upgrades.
package http

import (
	"bytes"
	"io/ioutil"
	"net/http"

	log "github.com/jensneuse/abstractlogger"
)

const (
	httpHeaderContentType string = "Content-Type"

	httpContentTypeApplicationJson string = "application/json"
)

func (g *GraphQLHTTPRequestHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		g.log.Error("GraphQLHTTPRequestHandler.handleHTTP",
			log.Error(err),
		)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	extra := &bytes.Buffer{}
	err = g.extraVariables(r, extra)
	if err != nil {
		g.log.Error("executionHandler.Handle.json.Marshal(extra)",
			log.Error(err),
		)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	executor, rootNode, ctx, err := g.executionHandler.Handle(data, extra.Bytes())
	if err != nil {
		g.log.Error("executionHandler.Handle",
			log.Error(err),
		)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx.Context = r.Context()
	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	err = executor.Execute(ctx, rootNode, buf)
	if err != nil {
		g.log.Error("executor.Execute",
			log.Error(err),
		)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add(httpHeaderContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
}
