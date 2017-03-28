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
		"prove_verify",
		"search",
	)

	RegisterTemplates(
		"create.html",
		"license.html",
		"login_register.html",
		"prove_verify.html",
		"search.html",
	)

	// Create request multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/create", TemplateHandler("create.html"))
	mux.HandleFunc("/license", TemplateHandler("license.html"))
	mux.HandleFunc("/login_register", TemplateHandler("login_register.html"))
	mux.HandleFunc("/prove_verify", TemplateHandler("prove_verify.html"))
	mux.HandleFunc("/search", TemplateHandler("search.html"))
	fs := http.Dir("static/")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(fs)))

	// Create api
	api := api.NewApi()

	// Add routes to multiplexer
	api.AddRoutes(mux)

	// Start HTTP server with multiplexer
	Println(http.ListenAndServe(":8888", mux))
}
