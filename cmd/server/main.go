package main

import (
    "log"
    "net/http"

    "github.com/gorilla/mux"
    "github.com/zharfatech/http-header-analyzer/internal/analyzer"
    "github.com/zharfatech/http-header-analyzer/internal/api"
)

func main() {
    // Initialize analyzer
    a := analyzer.NewAnalyzer()

    // Initialize API handler
    handler := api.NewHandler(a)

    // Set up router
    router := mux.NewRouter()

    // API routes
    apiRouter := router.PathPrefix("/api").Subrouter()
    apiRouter.HandleFunc("/analyze", handler.HandleAnalyze).Methods("POST")
    apiRouter.HandleFunc("/health", handler.HandleHealth).Methods("GET")

    // Web routes
    router.HandleFunc("/", handler.HandleIndex).Methods("GET")
    router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

    // Start server
    port := ":8080"
    log.Printf("HTTP Header Analyzer starting on port %s", port)
    log.Fatal(http.ListenAndServe(port, router))
}