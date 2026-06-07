package api

import (
    "encoding/json"
    "net/http"

    "github.com/zharfatech/http-header-analyzer/internal/analyzer"
    "github.com/zharfatech/http-header-analyzer/internal/validation"
)

// Handler holds dependencies for API handlers
type Handler struct {
    analyzer *analyzer.Analyzer
}

// NewHandler creates a new API handler
func NewHandler(a *analyzer.Analyzer) *Handler {
    return &Handler{
        analyzer: a,
    }
}

// HandleAnalyze handles the /api/analyze endpoint
func (h *Handler) HandleAnalyze(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Parse JSON body
    var request struct {
        URL string `json:"url"`
    }
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Validate URL
    validURL, err := validation.ValidateURL(request.URL)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(map[string]string{
            "error": err.Error(),
        })
        return
    }

    // Perform analysis
    result, err := h.analyzer.Analyze(validURL)
    if err != nil {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(map[string]string{
            "error": err.Error(),
        })
        return
    }

    // Return result
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(result)
}

// HandleHealth handles the /api/health endpoint
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "status": "healthy",
    })
}

// HandleIndex serves the main HTML page
func (h *Handler) HandleIndex(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/" {
        http.NotFound(w, r)
        return
    }
    http.ServeFile(w, r, "web/templates/index.html")
}

// HandleStatic serves static files
func (h *Handler) HandleStatic(w http.ResponseWriter, r *http.Request) {
    http.ServeFile(w, r, "web"+r.URL.Path)
}