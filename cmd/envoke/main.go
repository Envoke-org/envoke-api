package main

import (
	"net/http"

	"github.com/zbo14/envoke/api"
	. "github.com/zbo14/envoke/common"
)

func main() {

	CreatePages(
		"compose",
		"license",
		"login_register",
		"publish",
		"record",
		"release",
		"right",
	)

	RegisterTemplates(
		"compose.html",
		"license.html",
		"login_register.html",
		"publish.html",
		"record.html",
		"release.html",
		"right.html",
	)

	// Create request multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/compose", TemplateHandler("compose.html"))
	mux.HandleFunc("/license", TemplateHandler("license.html"))
	mux.HandleFunc("/login_register", TemplateHandler("login_register.html"))
	mux.HandleFunc("/publish", TemplateHandler("publish.html"))
	mux.HandleFunc("/record", TemplateHandler("record.html"))
	mux.HandleFunc("/release", TemplateHandler("release.html"))
	mux.HandleFunc("/right", TemplateHandler("recording_right.html"))
	fs := http.Dir("static/")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(fs)))

	// Create api
	api := api.NewApi()

	// Add routes to multiplexer
	api.AddRoutes(mux)

	// Start HTTP server with multiplexer
	Println(http.ListenAndServe(":8888", mux))
}
