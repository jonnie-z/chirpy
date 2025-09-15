package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jonnie-z/chirpy/internal/auth"
	"github.com/jonnie-z/chirpy/internal/database"
)

func addPutHandlers(c *apiConfig, mux *http.ServeMux) {
	mux.HandleFunc("PUT /api/users", c.updateUser)
}

type updateUserRequest struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type updateUserResponse struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

func (a *apiConfig) updateUser(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	updateUserRequest := updateUserRequest{}

	err := decoder.Decode(&updateUserRequest)
	if err != nil {
		log.Printf("Error decoding parameters: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	accessToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %s\n", err)

		respBody := errorResponse{
			Error: "Invalid bearer token",
		}

		respondError(w, 401, respBody)

		return
	}

	userId, err := auth.ValidateJWT(accessToken, a.serverSecret)
	if err != nil {
		log.Printf("Error validating JWT: %s\n", err)

		respBody := errorResponse{
			Error: "Unauthorized",
		}

		respondError(w, 401, respBody)

		return
	}

	usr, err := a.dbQueries.GetUserById(context.Background(), userId)
	if err != nil {
		log.Printf("Error getting user: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	pass, err := auth.HashPassword(updateUserRequest.Password)
	if err != nil {
		log.Printf("Error hashing password: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	params := database.UpdateUserParams{
		UpdatedAt:      time.Now().UTC(),
		Email:          updateUserRequest.Email,
		HashedPassword: pass,
		ID:             usr.ID,
	}

	updatedUsr, err := a.dbQueries.UpdateUser(context.Background(), params)
	if err != nil {
		log.Printf("Error updating user: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	respBody := updateUserResponse{
		ID:          updatedUsr.ID,
		CreatedAt:   updatedUsr.CreatedAt,
		UpdatedAt:   updatedUsr.UpdatedAt,
		Email:       updatedUsr.Email,
		IsChirpyRed: usr.IsChirpyRed,
	}

	respondJson(w, 200, respBody)

	log.Printf("User updated: %v", updatedUsr)
}
