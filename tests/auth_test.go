package tests

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jonnie-z/chirpy/internal/auth"
)

func TestHash(t *testing.T) {
	password := "wonky"
	actual, err := auth.HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing: %v\n", err)
	}

	if actual == password {
		t.Errorf("Password should have been hashed!\nPassword: %s\nActual: %s", password, actual)
	}
}

func TestCompareHash(t *testing.T) {
	password := "wonky"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Errorf("Error hashing: %v\n", err)
	}

	actual := auth.CheckPasswordHash(password, hash)

	if actual != nil {
		t.Errorf("Password hash should match!\nPassword: %s\nActual: %s", password, hash)
	}
}

func TestCreateJWT(t *testing.T) {
	tokenSecret := "wonky"
	expiresIn, err := time.ParseDuration("20s")
	if err != nil {
		t.Errorf("Error parsing duration: %v\n", err)
	}

	userID := uuid.New()
	signedJWT, err := auth.MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Errorf("Error making JWT: %v\n", err)
	}

	actual, err := auth.ValidateJWT(signedJWT, tokenSecret)
	if err!= nil {
		t.Errorf("Error validating JWT: %v\n", err)
	}

	if userID != actual {
		t.Errorf("UUIDs should match!")
	}
}

func TestBearerToken(t *testing.T) {
	authorization := ""
	headers := http.Header{}
	headers.Set("Authorization", authorization)
	_, err := auth.GetBearerToken(headers)
	if err == nil {
		t.Error("err: No authorization header should throw err!\n")
	}

	authorization = "Bearer abc123"
	headers.Set("Authorization", authorization)
	token, err := auth.GetBearerToken(headers)
	if err != nil {
		t.Errorf("err: Authorization header should not throw err! %v\n", err)
	}

	if token != "abc123" {
		t.Errorf("Incorrect token! %s", token)
	}

	authorization = "abc123"
	headers.Set("Authorization", authorization)
	_, err = auth.GetBearerToken(headers)
	if err == nil {
		t.Errorf("err: Incorrrect header format should throw err!\n")
	}
}