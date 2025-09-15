package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jonnie-z/chirpy/internal/auth"
	"github.com/jonnie-z/chirpy/internal/database"
)

func addPostHandlers(c *apiConfig, mux *http.ServeMux) {
	mux.HandleFunc("POST /admin/reset", c.reset)
	mux.Handle("POST /api/validate_chirp", validateChirpHandler{})
	mux.HandleFunc("POST /api/users", c.createUser)
	mux.HandleFunc("POST /api/chirps", c.createChirp)
	mux.HandleFunc("POST /api/login", c.login)
	mux.HandleFunc("POST /api/refresh", c.refresh)
	mux.HandleFunc("POST /api/revoke", c.revoke)
	mux.HandleFunc("POST /api/polka/webhooks", c.polkaWebhook)
}

type polkaWebhookRequest struct {
	Event string `json:"event"`
	Data  struct {
		UserId uuid.UUID `json:"user_id"`
	} `json:"data"`
}

func (a *apiConfig) polkaWebhook(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	polkaWebhookRequest := polkaWebhookRequest{}

	err := decoder.Decode(&polkaWebhookRequest)
	if err != nil {
		log.Printf("Error decoding parameters: %v\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	requestApiKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 401, respBody)

		return
	}

	if requestApiKey != a.polkaKey {
		log.Printf("Error getting bearer token: %s\n", err)

		respBody := errorResponse{
			Error: "Unauthorized",
		}

		respondError(w, 401, respBody)

		return
	}

	if polkaWebhookRequest.Event != "user.upgraded" {
		respondJson(w, 204, "")

		return
	}

	usr, err := a.dbQueries.UpgradeUser(context.Background(), polkaWebhookRequest.Data.UserId)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			log.Printf("User not found: %s\n", err)

			respBody := errorResponse{
				Error: "User Not Found",
			}

			respondError(w, 404, respBody)

			return
		}

		log.Printf("Error upgrading user: %v\n", err)

		respBody := errorResponse{
			Error: "Error upgrading user",
		}

		respondError(w, 500, respBody)

		return
	}

	respondJson(w, 204, "")

	fmt.Printf("%v\n", usr)

}

func (a *apiConfig) revoke(w http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 401, respBody)

		return
	}

	dbRefreshToken, err := a.dbQueries.GetRefreshToken(context.Background(), refreshToken)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			log.Printf("Refresh Token not found: %s\n", err)

			respBody := errorResponse{
				Error: "Invalid refresh token",
			}

			respondError(w, 401, respBody)

			return
		}

		log.Printf("Error getting bearer token: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	if dbRefreshToken.RevokedAt != (sql.NullTime{Valid: false}) {
		log.Printf("Refresh token already revoked: %v\n", dbRefreshToken)

		respBody := errorResponse{
			Error: "Refresh token already revoked",
		}

		respondError(w, 401, respBody)

		return
	}

	params := database.RevokeRefreshTokenParams{
		RevokedAt: sql.NullTime{
			Valid: true,
			Time:  time.Now().UTC(),
		},
		UpdatedAt: time.Now().UTC(),
		Token:     dbRefreshToken.Token,
	}

	a.dbQueries.RevokeRefreshToken(context.Background(), params)

	respondJson(w, 204, "")

	log.Printf("User token revoked\n")
}

type refreshResponse struct {
	Token string `json:"token"`
}

func (a *apiConfig) refresh(w http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		log.Printf("Error getting bearer token: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 401, respBody)

		return
	}

	dbRefreshToken, err := a.dbQueries.GetRefreshToken(context.Background(), refreshToken)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			log.Printf("Refresh Token not found: %s\n", err)

			respBody := errorResponse{
				Error: "Invalid refresh token",
			}

			respondError(w, 401, respBody)

			return
		}

		log.Printf("Error getting bearer token: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	if dbRefreshToken.RevokedAt != (sql.NullTime{Valid: false}) {
		log.Printf("Refresh token already revoked: %v\n", dbRefreshToken)

		respBody := errorResponse{
			Error: "Refresh token revoked",
		}

		respondError(w, 401, respBody)

		return
	}

	if dbRefreshToken.ExpiresAt.Before(time.Now().UTC()) {
		log.Printf("Refresh token expired: %v\n", dbRefreshToken)

		respBody := errorResponse{
			Error: "Refresh token expired",
		}

		respondError(w, 401, respBody)

		return
	}

	expiresIn, err := time.ParseDuration(fmt.Sprintf("%ds", 3600))
	if err != nil {
		log.Printf("Error parsing duration: %v\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	accessToken, err := auth.MakeJWT(dbRefreshToken.UserID, a.serverSecret, expiresIn)
	if err != nil {
		log.Printf("Error making JWT: %v\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	respBody := refreshResponse{
		Token: accessToken,
	}

	respondJson(w, 200, respBody)

	log.Printf("User token refreshed\n")
}

type loginRequest struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type loginResponse struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

func (a *apiConfig) login(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	loginRequest := loginRequest{}

	err := decoder.Decode(&loginRequest)
	if err != nil {
		log.Printf("Error decoding parameters: %v\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	usr, err := a.dbQueries.GetUserByEmail(context.Background(), loginRequest.Email)
	if err != nil {
		log.Printf("Error getting user: %v\n", err)

		respBody := errorResponse{
			Error: "User not found for email: " + loginRequest.Email,
		}

		respondError(w, 404, respBody)

		return
	}

	err = auth.CheckPasswordHash(loginRequest.Password, usr.HashedPassword)
	if err != nil {
		log.Printf("Error authenticating user: %v\n", err)

		respBody := errorResponse{
			Error: "Incorrect email or password",
		}

		respondError(w, 401, respBody)

		return
	}

	expiresIn, err := time.ParseDuration(fmt.Sprintf("%ds", 3600))
	if err != nil {
		log.Printf("Error parsing duration: %v\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	token, err := auth.MakeJWT(usr.ID, a.serverSecret, expiresIn)
	if err != nil {
		log.Printf("Error making JWT: %v\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	refreshToken := auth.MakeRefreshToken()

	params := database.CreateRefreshTokenParams{
		Token:     refreshToken,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().AddDate(0, 0, 60),
		RevokedAt: sql.NullTime{
			Valid: false,
		},
		UserID: usr.ID,
	}

	_, err = a.dbQueries.CreateRefreshToken(context.Background(), params)
	if err != nil {
		log.Printf("Error creating refresh token: %v\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	respBody := loginResponse{
		ID:           usr.ID,
		CreatedAt:    usr.CreatedAt,
		UpdatedAt:    usr.UpdatedAt,
		Email:        usr.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  usr.IsChirpyRed,
	}

	respondJson(w, 200, respBody)

	log.Printf("User logged in: %v\n", usr)
}

type createChirpRequest struct {
	Body string `json:"body"`
}

type chirpResponse struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (a *apiConfig) createChirp(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	chirpRequest := createChirpRequest{}

	err := decoder.Decode(&chirpRequest)
	if err != nil {
		log.Printf("Error decoding parameters: %s\n", err)

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

	params := database.CreateChirpParams{
		ID:        uuid.New(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Body:      chirpRequest.Body,
		UserID:    userId,
	}

	chirp, err := a.dbQueries.CreateChirp(context.Background(), params)
	if err != nil {
		log.Printf("Error creating chirp: %s\n", err)

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

	respondJson(w, 201, respBody)

	log.Printf("Chirp created: %v\n", chirp)
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type createUserResponse struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	HashedPassword string    `json:"hashed_password"`
	IsChirpyRed    bool      `json:"is_chirpy_red"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (a *apiConfig) createUser(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	userRequest := createUserRequest{}

	err := decoder.Decode(&userRequest)
	if err != nil {
		log.Printf("Error decoding parameters: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	if userRequest.Password == "" {
		log.Printf("No password given: %v\n", userRequest)

		respBody := errorResponse{
			Error: "Password required!",
		}

		respondError(w, 400, respBody)

		return
	}

	hash, err := auth.HashPassword(userRequest.Password)
	if err != nil {
		log.Printf("Error hashing password: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	params := database.CreateUserParams{
		ID:             uuid.New(),
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
		Email:          userRequest.Email,
		HashedPassword: hash,
	}

	usr, err := a.dbQueries.CreateUser(context.Background(), params)
	if err != nil {
		log.Printf("Error creating user: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 500, respBody)

		return
	}

	respBody := createUserResponse{
		ID:             usr.ID,
		CreatedAt:      usr.CreatedAt,
		UpdatedAt:      usr.UpdatedAt,
		Email:          usr.Email,
		HashedPassword: usr.HashedPassword,
		IsChirpyRed:    usr.IsChirpyRed,
	}

	respondJson(w, 201, respBody)

	log.Printf("User created: %v", usr)
}

func getBlockList() []string {
	return []string{
		"kerfuffle",
		"sharbert",
		"fornax",
	}
}

type validateChirpRequest struct {
	Body string `json:"body"`
}

type validateChirpResponse struct {
	Valid       bool   `json:"valid"`
	CleanedBody string `json:"cleaned_body"`
}

type successResponse struct {
	Success bool   `json:"success"`
	Body    string `json:"body"`
}

type validateChirpHandler struct{}

func respondError(w http.ResponseWriter, code int, payload any) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s\n", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func respondJson(w http.ResponseWriter, code int, payload any) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshalling JSON: %s\n", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func (validateChirpHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	validation := validateChirpRequest{}

	err := decoder.Decode(&validation)
	if err != nil {
		log.Printf("Error decoding parameters: %s\n", err)

		respBody := errorResponse{
			Error: "Something went wrong",
		}

		respondError(w, 400, respBody)

		return
	}

	if len(validation.Body) > 140 {
		respBody := errorResponse{
			Error: "Chirp is too long",
		}

		respondError(w, 400, respBody)

		return
	}

	cleanedBody := checkProfanity(validation.Body)

	respBody := validateChirpResponse{
		Valid:       true,
		CleanedBody: cleanedBody,
	}

	respondJson(w, 200, respBody)
}

func checkProfanity(validationBody string) string {
	blockList := getBlockList()

	words := strings.Split(validationBody, " ")

	for i, word := range words {
		if slices.Contains(blockList, strings.ToLower(word)) {
			words[i] = "****"
		}
	}

	return strings.Join(words, " ")
}

func (a *apiConfig) reset(w http.ResponseWriter, _ *http.Request) {
	a.fileserverHits.Store(0)
	err := a.dbQueries.DeleteUsers(context.Background())
	if err != nil {
		log.Printf("ERR: %v\n", err)

		respBody := errorResponse{
			Error: "ERROR ENCOUNTED IN RESET",
		}

		respondError(w, 400, respBody)
	} else {
		log.Println("Metrics Reset :: Users Deleted")
	}

	respBody := successResponse{
		Success: true,
		Body:    "Metrics and Users Reset",
	}

	respondJson(w, 200, respBody)
}
