package gateway

import (
	"github.com/TykTechnologies/tyk/internal/middleware"
	"github.com/rs/cors"
	"net/http"
)

type CORSMiddleware struct {
	*BaseMiddleware
	corsHandler *cors.Cors
}

func (c *CORSMiddleware) Name() string {
	return "CORSMiddleware"
}

func (c *CORSMiddleware) EnabledForSpec() bool {
	return c.Spec.CORS.Enable
}

func (c *CORSMiddleware) Init() {
	c.corsHandler = cors.New(cors.Options{
		AllowedOrigins:     c.Spec.CORS.AllowedOrigins,
		AllowedMethods:     c.Spec.CORS.AllowedMethods,
		AllowedHeaders:     c.Spec.CORS.AllowedHeaders,
		ExposedHeaders:     c.Spec.CORS.ExposedHeaders,
		AllowCredentials:   c.Spec.CORS.AllowCredentials,
		MaxAge:             c.Spec.CORS.MaxAge,
		OptionsPassthrough: c.Spec.CORS.OptionsPassthrough,
		Debug:              c.Spec.CORS.Debug,
	})
}

func (c *CORSMiddleware) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	c.corsHandler.HandlerFunc(w, r)

	if r.Method == http.MethodOptions && !c.Spec.CORS.OptionsPassthrough {
		return nil, middleware.StatusRespond
	}

	return nil, http.StatusOK
}
