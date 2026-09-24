package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/zharfatech/http-header-analyzer/internal/analyzer"
	"github.com/zharfatech/http-header-analyzer/internal/api"
)

func main() {
	a := analyzer.NewAnalyzer()
	handler := api.NewHandler(a)

	router := mux.NewRouter()
	router.Use(securityHeaders)

	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.HandleFunc("/analyze", handler.HandleAnalyze).Methods(http.MethodPost)
	apiRouter.HandleFunc("/report", handler.HandleReport).Methods(http.MethodPost)
	apiRouter.HandleFunc("/health", handler.HandleHealth).Methods(http.MethodGet)

	router.HandleFunc("/", handler.HandleIndex).Methods(http.MethodGet)
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))

	addr := ":" + envOrDefault("PORT", "8080")
	server := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("HTTP Header Analyzer listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
