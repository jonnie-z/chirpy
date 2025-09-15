package main

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jonnie-z/chirpy/internal/auth"
)

func addDeleteHandlers(c *apiConfig, mux *http.ServeMux) {
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", c.deleteChirp)
}

func (a *apiConfig) deleteChirp(w http.ResponseWriter, req *http.Request) {
	chirpID, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		log.Printf("Error parsing UUID: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Error getting Bearer token: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 401, respBody)

		return
	}

	userId, err := auth.ValidateJWT(token, a.serverSecret)
	if err != nil {
		log.Printf("Error validating JWT: %s\n", err)

		respBody := errorResponse{
			Error: "Unauthorized",
		}

		respondError(w, 401, respBody)

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

	if userId != chirp.UserID {
		log.Printf("User not author of Chirp\n")

		respBody := errorResponse{
			Error: "Unauthorized",
		}

		respondError(w, 403, respBody)

		return
	}

	// jz eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjaGlycHktYWNjZXNzIiwic3ViIjoiNjc4MmY0NjEtZTdlMS00ZGMzLTllNzItNDIyODViM2FiMjU5IiwiZXhwIjoxNzU3OTA1MTc5LCJpYXQiOjE3NTc5MDE1Nzl9.xP9MvsZpA8q4p8n54-9HYEvTvf-M4cGcmxATgmBpt6k
	// ja eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjaGlycHktYWNjZXNzIiwic3ViIjoiZTFlYTA5MTktZjU1Ny00NjI2LWFhZGQtZTZhNzk1ZjkzZjA4IiwiZXhwIjoxNzU3OTA1MjA4LCJpYXQiOjE3NTc5MDE2MDh9.hSssHic9bxESYgZ_a3EiSuhIYCSC0rZ_AfG-GvL6Loo

	err = a.dbQueries.DeleteChirp(context.Background(), chirpID)
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

	respondJson(w, 204, "")

	log.Println("Chirp deleted")
}