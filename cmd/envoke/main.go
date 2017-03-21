package main

import (
	"net/http"

	"github.com/zbo14/envoke/api"
	. "github.com/zbo14/envoke/common"
)

func main() {

	CreatePages(
		"compose",
		"master_license",
		"mechanical_license",
		"login_register",
		"publish",
		"record",
		"release",
		"composition_right",
		"recording_right",
	)

	RegisterTemplates(
		"compose.html",
		"master_license.html",
		"mechanical_license.html",
		"login_register.html",
		"publish.html",
		"record.html",
		"release.html",
		"composition_right.html",
		"recording_right.html",
	)

	// Create request multiplexer
	mux := http.NewServeMux()
	mux.HandleFunc("/compose", TemplateHandler("compose.html"))
	mux.HandleFunc("/master_license", TemplateHandler("master_license.html"))
	mux.HandleFunc("/mechanical_license", TemplateHandler("mechanical_license.html"))
	mux.HandleFunc("/login_register", TemplateHandler("login_register.html"))
	mux.HandleFunc("/publish", TemplateHandler("publish.html"))
	mux.HandleFunc("/record", TemplateHandler("record.html"))
	mux.HandleFunc("/release", TemplateHandler("release.html"))
	mux.HandleFunc("/composition_right", TemplateHandler("composition_right.html"))
	mux.HandleFunc("/recording_right", TemplateHandler("recording_right.html"))
	fs := http.Dir("static/")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(fs)))

	// Create api
	api := api.NewApi()

	// Add routes to multiplexer
	api.AddRoutes(mux)

	// Start HTTP server with multiplexer
	Println(http.ListenAndServe(":8888", mux))
}
