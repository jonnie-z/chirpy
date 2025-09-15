package main

import (
	"net/http"
)

func addHandlers(c *apiConfig, mux *http.ServeMux) {
	addGetHandlers(c, mux)
	addPostHandlers(c, mux)
	addPutHandlers(c, mux)
	addDeleteHandlers(c, mux)
}


