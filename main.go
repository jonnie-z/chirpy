package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/joho/godotenv"
	"github.com/jonnie-z/chirpy/internal/database"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      database.Queries
	serverSecret   string
	polkaKey       string
}

func main() {
	godotenv.Load()
	secret := os.Getenv("SERVER_SECRET")

	dbURL := os.Getenv("DB_URL")
	polkaKey := os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("ERR OPENING DB")
	}

	c := apiConfig{
		dbQueries:    *database.New(db),
		serverSecret: secret,
		polkaKey:     polkaKey,
	}
	mux := http.NewServeMux()

	addHandlers(&c, mux)

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	server.ListenAndServe()
}
