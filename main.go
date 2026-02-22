package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(lrw, r)

		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, lrw.statusCode, time.Since(start).Round(time.Millisecond))
	})
}

func trace404Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)
		if lrw.statusCode == http.StatusNotFound {
			log.Printf("404 trace: method=%s path=%s query=%s", r.Method, r.URL.Path, r.URL.RawQuery)
			debug.PrintStack()
		}
	})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowedOrigins := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))

		if allowedOrigins == "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			for _, o := range strings.Split(allowedOrigins, ",") {
				if strings.TrimSpace(o) == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	if err := loadEnvFile(".env"); err != nil {
		log.Printf("failed to load .env: %v", err)
	}
	initJWKS()

	mux := http.NewServeMux()

	mux.HandleFunc("/health", healthHandler)
	mux.Handle("/protected", ClerkMiddleware(http.HandlerFunc(protectedHandler)))

	registerProductRoutes(mux)
	registerAPIRoutes(mux)
	registerCartRoutes(mux)
	registerOrderRoutes(mux)

	handler := requestLogger(trace404Middleware(corsMiddleware(mux)))

	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := FromContext(r.Context())
	if !ok || user == nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id":         user.ID,
		"email":      user.Email,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
	})
}
