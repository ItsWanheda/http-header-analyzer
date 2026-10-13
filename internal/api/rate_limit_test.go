package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimitMiddlewareRejectsRequestsAfterLimit(t *testing.T) {
	rateBuckets.Lock()
	rateBuckets.clients = make(map[string]rateBucket)
	rateBuckets.Unlock()

	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.WriteHeader(http.StatusNoContent) })
	handler := RateLimitMiddleware(next)
	for i := 0; i < apiRateLimit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/example", nil)
		req.RemoteAddr = "198.51.100.55:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent { t.Fatalf("request %d status = %d, want 204", i+1, rec.Code) }
	}
	req := httptest.NewRequest(http.MethodGet, "/api/example", nil)
	req.RemoteAddr = "198.51.100.55:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests { t.Fatalf("over-limit status = %d, want 429", rec.Code) }
	if rec.Header().Get("Retry-After") == "" { t.Fatal("429 response lacks Retry-After") }
	if called != apiRateLimit { t.Fatalf("next handler called %d times, want %d", called, apiRateLimit) }

	health := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	health.RemoteAddr = "198.51.100.55:1234"
	healthRec := httptest.NewRecorder()
	handler.ServeHTTP(healthRec, health)
	if healthRec.Code != http.StatusNoContent { t.Fatalf("health check passed through status = %d, want 204", healthRec.Code) }

	rateBuckets.Lock()
	for key, value := range rateBuckets.clients { if time.Since(value.start) >= apiRateWindow { delete(rateBuckets.clients, key) } }
	rateBuckets.Unlock()
}
