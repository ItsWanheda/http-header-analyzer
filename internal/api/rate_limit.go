package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	apiRateWindow = time.Minute
	apiRateLimit  = 20
	maxRateKeys   = 4096
)

type rateBucket struct {
	start time.Time
	count int
}

var rateBuckets = struct {
	sync.Mutex
	clients map[string]rateBucket
}{clients: make(map[string]rateBucket)}

// RateLimitMiddleware applies a bounded, process-local fixed-window limit to
// API calls. It deliberately trusts RemoteAddr rather than arbitrary forwarded
// headers; configure trusted-proxy handling at the deployment edge if needed.
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
		if err != nil || host == "" {
			host = strings.TrimSpace(r.RemoteAddr)
		}
		now := time.Now()
		rateBuckets.Lock()
		bucket, ok := rateBuckets.clients[host]
		if !ok || now.Sub(bucket.start) >= apiRateWindow {
			bucket = rateBucket{start: now}
		}
		if bucket.count >= apiRateLimit {
			retry := int(apiRateWindow.Seconds() - now.Sub(bucket.start).Seconds())
			if retry < 1 { retry = 1 }
			rateBuckets.Unlock()
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "API rate limit exceeded; retry shortly"})
			return
		}
		bucket.count++
		rateBuckets.clients[host] = bucket
		if len(rateBuckets.clients) > maxRateKeys {
			for key, value := range rateBuckets.clients {
				if now.Sub(value.start) >= apiRateWindow {
					delete(rateBuckets.clients, key)
				}
			}
			if len(rateBuckets.clients) > maxRateKeys {
				for key := range rateBuckets.clients {
					if key != host {
						delete(rateBuckets.clients, key)
						break
					}
				}
			}
		}
		rateBuckets.Unlock()
		next.ServeHTTP(w, r)
	})
}
