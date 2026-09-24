package api

import (
	"encoding/json"
	"net/http"

	"github.com/zharfatech/http-header-analyzer/internal/analyzer"
	"github.com/zharfatech/http-header-analyzer/internal/validation"
)

const maxRequestBody = 8 << 10

type Handler struct { analyzer *analyzer.Analyzer }

func NewHandler(a *analyzer.Analyzer) *Handler { return &Handler{analyzer: a} }

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}




func (h *Handler) HandleAnalyze(w http.ResponseWriter, r *http.Request) {
	var request struct { URL string `json:"url"` }
	if err := decodeJSON(w, r, &request); err != nil { writeJSON(w, http.StatusBadRequest, map[string]string{"error":"invalid request body"}); return }
	validURL, err := validation.ValidateURL(request.URL)
	if err != nil { writeJSON(w, http.StatusBadRequest, map[string]string{"error":err.Error()}); return }
	result, err := h.analyzer.AnalyzeWithContext(r.Context(), validURL)
	if err != nil { writeJSON(w, http.StatusBadGateway, map[string]string{"error":"analysis failed"}); return }
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, map[string]string{"status":"healthy"}) }

func (h *Handler) HandleIndex(w http.ResponseWriter, r *http.Request) { if r.URL.Path != "/" { http.NotFound(w,r); return }; http.ServeFile(w,r,"web/templates/index.html") }

func (h *Handler) HandleStatic(w http.ResponseWriter, r *http.Request) { http.ServeFile(w,r,"web"+r.URL.Path) }