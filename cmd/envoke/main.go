package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/zbo14/envoke/api"
)

func main() {

	// Create http router
	router := httprouter.New()

	// Create api and add routes to multiplexer
	api.NewApi().AddRoutes(router)

	// Start HTTP server with router
	http.ListenAndServe(":8888", router)
}
