package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ItsWanheda/http-header-analyzer/internal/analyzer"
)

func TestHandleAnalyzeRejectsUnsafeTargetBeforeNetworkAccess(t *testing.T) {
	h := NewHandler(analyzer.NewAnalyzer())
	req := httptest.NewRequest(http.MethodPost, "/api/analyze", strings.NewReader(`{"url":"http://127.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleAnalyze(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleBatchValidatesAllTargetsBeforeStarting(t *testing.T) {
	h := NewHandler(analyzer.NewAnalyzer())
	req := httptest.NewRequest(http.MethodPost, "/api/analyze/batch", strings.NewReader(`{"urls":["https://example.com","http://169.254.169.254"]}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.HandleBatch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleBatchCapsTargetCount(t *testing.T) {
	h := NewHandler(analyzer.NewAnalyzer())
	req := httptest.NewRequest(http.MethodPost, "/api/analyze/batch", strings.NewReader(`{"urls":["https://example.com","https://example.org","https://example.net","https://iana.org","https://wikipedia.org","https://golang.org","https://github.com","https://go.dev","https://openai.com","https://example.edu","https://example.io"]}`))
	rec := httptest.NewRecorder()
	h.HandleBatch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHealthReturnsVersionAndNoStore(t *testing.T) {
	h := NewHandler(analyzer.NewAnalyzer())
	rec := httptest.NewRecorder()
	h.HandleHealth(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if rec.Code != http.StatusOK { t.Fatalf("status = %d, want 200", rec.Code) }
	if rec.Header().Get("Cache-Control") != "no-store" { t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control")) }
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil { t.Fatal(err) }
	if body["status"] != "healthy" || body["version"] == "" { t.Fatalf("unexpected health payload: %#v", body) }
}
