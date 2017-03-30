package main

import (
	"net/http"

	"github.com/zbo14/envoke/api"
	. "github.com/zbo14/envoke/common"
)

func main() {

	CreatePages(
		"create",
		"license",
		"login_register",
		"search",
		"verification",
	)

	RegisterTemplates(
		"create.html",
		"license.html",
		"login_register.html",
		"search.html",
		"verification.html",
	)

	// Create request multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/create", TemplateHandler("create.html"))
	// mux.HandleFunc("/license", TemplateHandler("license.html"))
	mux.HandleFunc("/login_register", TemplateHandler("login_register.html"))
	mux.HandleFunc("/verification", TemplateHandler("verification.html"))
	fs := http.Dir("static/")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(fs)))

	// Create api and add routes to multiplexer
	api.NewApi().AddRoutes(mux)

	// Start HTTP server with multiplexer
	http.ListenAndServe(":8888", mux)
}
