package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func addGetHandlers(c *apiConfig, mux *http.ServeMux) {
	mux.Handle("/app/", http.StripPrefix("/app", c.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	mux.Handle("GET /admin/metrics", c)
	mux.Handle("GET /api/healthz", readinessHandler{})
	mux.HandleFunc("GET /api/chirps", c.getChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", c.getChirp)
}

func (a *apiConfig) getChirp(w http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		log.Printf("Error parsing UUID: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	chirp, err := a.dbQueries.GetChirp(context.Background(), chirpID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			log.Printf("Chirp not found: %s\n", err)

			respBody := errorResponse{
				Error: "Chirp Not Found",
			}

			respondError(w, 404, respBody)

			return
		}

		log.Printf("Error getting Chirps: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	respBody := chirpResponse{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}

	respondJson(w, 200, respBody)

	log.Println("Chirp requested")

}

func (a *apiConfig) getChirps(w http.ResponseWriter, req *http.Request) {
	chirps, err := a.dbQueries.GetChirps(context.Background())
	if err != nil {
		log.Printf("Error getting Chirps: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 400, respBody)

		return
	}

	respBody := []chirpResponse{}

	for _, chirp := range chirps {
		chirpResponse := chirpResponse{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		}

		respBody = append(respBody, chirpResponse)
	}

	respondJson(w, 200, respBody)

	log.Println("Chirps requested")

}

func (a *apiConfig) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(200)
	templateString := `
<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
</html>
`
	fmt.Fprintf(w, templateString, a.fileserverHits.Load())
}

func (a *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		a.fileserverHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

type readinessHandler struct{}

func (readinessHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}
