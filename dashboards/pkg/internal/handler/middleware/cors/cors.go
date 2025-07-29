package cors

import (
	"net/http"

	"github.com/rs/cors"
)

func NewMiddleware(origins []string, next http.Handler) http.Handler {

	return cors.New(cors.Options{
		AllowedOrigins: origins,
		AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodHead, http.MethodOptions},
		AllowedHeaders: []string{"authorization", "content-type", "x-project-id", "x-tenant-id", "x-cluster-id"},
	}).Handler(next)
}
