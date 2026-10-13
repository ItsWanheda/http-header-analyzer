package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ItsWanheda/http-header-analyzer/internal/analyzer"
	"github.com/ItsWanheda/http-header-analyzer/internal/models"
	"github.com/ItsWanheda/http-header-analyzer/internal/validation"
)

const (
	maxRequestBody       = 64 << 10
	maxBatchTargets      = 10
	maxConcurrentScans   = 4
	maxBatchConcurrency  = 3
)

var errScanCapacity = errors.New("scanner is at capacity")

type Handler struct {
	analyzer  *analyzer.Analyzer
	scanSlots chan struct{}
}

func NewHandler(a *analyzer.Analyzer) *Handler {
	return &Handler{analyzer: a, scanSlots: make(chan struct{}, maxConcurrentScans)}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request must contain one JSON value")
		}
		return err
	}
	return nil
}

func (h *Handler) acquireScanSlot(ctx context.Context) bool {
	select {
	case h.scanSlots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	default:
		return false
	}
}

func (h *Handler) releaseScanSlot() {
	<-h.scanSlots
}

func (h *Handler) HandleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var request struct {
		URL string `json:"url"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	validURL, err := validation.ValidateURL(request.URL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !h.acquireScanSlot(r.Context()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": errScanCapacity.Error()})
		return
	}
	defer h.releaseScanSlot()

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := h.analyzer.AnalyzeWithContext(ctx, validURL)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "analysis timed out"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "analysis failed"})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type batchScanItem struct {
	URL    string                 `json:"url"`
	Result *models.AnalysisResult `json:"result,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

type batchScanResponse struct {
	Total   int             `json:"total"`
	Results []batchScanItem `json:"results"`
}

func (h *Handler) HandleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var request struct {
		URLs []string `json:"urls"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if len(request.URLs) == 0 || len(request.URLs) > maxBatchTargets {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("provide between 1 and %d target URLs", maxBatchTargets)})
		return
	}
	validURLs := make([]string, len(request.URLs))
	for i, target := range request.URLs {
		valid, err := validation.ValidateURL(target)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("target %d: %s", i+1, err.Error())})
			return
		}
		validURLs[i] = valid
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	response := batchScanResponse{Total: len(validURLs), Results: make([]batchScanItem, len(validURLs))}
	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := maxBatchConcurrency
	if len(validURLs) < workers {
		workers = len(validURLs)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				item := batchScanItem{URL: validURLs[index]}
				if !h.acquireScanSlot(ctx) {
					item.Error = "scan cancelled or scanner at capacity"
					response.Results[index] = item
					continue
				}
				result, err := h.analyzer.AnalyzeWithContext(ctx, validURLs[index])
				h.releaseScanSlot()
				if err != nil {
					item.Error = "analysis failed or timed out"
				} else {
					item.Result = result
				}
				response.Results[index] = item
			}
		}()
	}
	for index := range validURLs {
		select {
		case jobs <- index:
		case <-ctx.Done():
			response.Results[index] = batchScanItem{URL: validURLs[index], Error: "batch scan cancelled or timed out"}
		}
	}
	close(jobs)
	wg.Wait()
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy", "version": "1.0.0"})
}

func (h *Handler) HandleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "web/templates/index.html")
}

func (h *Handler) HandleStatic(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "web"+r.URL.Path)
}
