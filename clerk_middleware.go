package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

// contextKey is a private type preventing context key collisions with other packages.
type contextKey string

const clerkUserKey contextKey = "clerk_user"

type ClerkUser struct {
	ID        string    `json:"id"`
	Email     string    `json:"email_address"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	LastLogin time.Time `json:"last_login"`
}

var jwks *keyfunc.JWKS

type clerkUserCacheEntry struct {
	user      *ClerkUser
	expiresAt time.Time
}

var (
	clerkUserCacheMu sync.RWMutex
	clerkUserCache   = map[string]clerkUserCacheEntry{}
)

func init() {
	initJWKS()
}

func initJWKS() {
	// initialize JWKS on startup if env is present
	frontend := os.Getenv("CLERK_FRONTEND_API_URL")
	if frontend == "" {
		return
	}
	jwksURL := strings.TrimRight(frontend, "/") + "/.well-known/jwks.json"
	var err error
	jwks, err = keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshInterval:   time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
		RefreshErrorHandler: func(err error) {
			log.Printf("jwks refresh error: %v", err)
		},
	})
	if err != nil {
		logErrorWithTrace("failed to get JWKS", err)
	}
}

// ClerkMiddleware validates Clerk JWT (if provided) and attaches user info into context.
// If no Authorization header is present, the middleware simply calls next.
func ClerkMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			if isPublicProductReadRequest(r) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "invalid authorization header", http.StatusUnauthorized)
			return
		}
		tokenString := parts[1]

		if jwks == nil {
			// attempt to (re)initialize
			initJWKS()
			if jwks == nil {
				http.Error(w, "jwks not configured", http.StatusInternalServerError)
				return
			}
		}

		token, err := jwt.Parse(tokenString, jwks.Keyfunc)
		if err != nil || !token.Valid {
			logErrorWithTrace("invalid token parse/validation", err)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "invalid token claims", http.StatusUnauthorized)
			return
		}

		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			http.Error(w, "user id not found in token", http.StatusUnauthorized)
			return
		}

		// Always keep auth user from JWT subject, even if Clerk profile fetch fails.
		user := &ClerkUser{
			ID:        sub,
			Email:     "",
			FirstName: "",
			LastName:  "",
		}
		info, err := fetchClerkUserCached(sub)
		if err != nil {
			logErrorWithTrace("failed to fetch clerk user info for sub="+sub, err)
		} else {
			user = info
		}

		if _, err := ensureCustomUserFromClerk(r.Context(), user); err != nil {
			logErrorWithTrace("failed to sync custom user for clerk_id="+user.ID, err)
		}

		ctx := context.WithValue(r.Context(), clerkUserKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isPublicProductReadRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	path := strings.TrimSpace(r.URL.Path)
	for strings.HasSuffix(path, "/") && len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	if path == "/api/products" || path == "/products" {
		return true
	}

	// Allow GET /api/products/{id} and GET /products/{id} without auth.
	if strings.HasPrefix(path, "/api/products/") {
		rawID := strings.TrimPrefix(path, "/api/products/")
		if rawID == "" || strings.Contains(rawID, "/") {
			return false
		}
		_, err := strconv.ParseInt(rawID, 10, 64)
		return err == nil
	}
	if strings.HasPrefix(path, "/products/") {
		rawID := strings.TrimPrefix(path, "/products/")
		if rawID == "" || strings.Contains(rawID, "/") {
			return false
		}
		_, err := strconv.ParseInt(rawID, 10, 64)
		return err == nil
	}
	return false
}

func fetchClerkUser(userID string) (*ClerkUser, error) {
	apiURL := os.Getenv("CLERK_API_URL")
	if apiURL == "" {
		apiURL = "https://api.clerk.com/v1"
	}
	apiURL = strings.TrimRight(apiURL, "/")
	if !strings.HasSuffix(apiURL, "/v1") {
		apiURL = apiURL + "/v1"
	}
	secret := os.Getenv("CLERK_SECRET_KEY")
	if secret == "" {
		return nil, errors.New("CLERK_SECRET_KEY not set")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/users/%s", apiURL, userID), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", secret))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("clerk returned status %d", resp.StatusCode)
	}

	var data struct {
		ID             string `json:"id"`
		FirstName      string `json:"first_name"`
		LastName       string `json:"last_name"`
		EmailAddresses []struct {
			Email string `json:"email_address"`
		} `json:"email_addresses"`
		LastSignInAt int64 `json:"last_sign_in_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	email := ""
	if len(data.EmailAddresses) > 0 {
		email = data.EmailAddresses[0].Email
	}

	var lastLogin time.Time
	if data.LastSignInAt > 0 {
		// Clerk returns milliseconds
		lastLogin = time.UnixMilli(data.LastSignInAt)
	}

	return &ClerkUser{
		ID:        data.ID,
		Email:     email,
		FirstName: data.FirstName,
		LastName:  data.LastName,
		LastLogin: lastLogin,
	}, nil
}

func fetchClerkUserCached(userID string) (*ClerkUser, error) {
	ttl := clerkUserCacheTTL()

	clerkUserCacheMu.RLock()
	entry, ok := clerkUserCache[userID]
	clerkUserCacheMu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) && entry.user != nil {
		u := *entry.user
		return &u, nil
	}

	user, err := fetchClerkUser(userID)
	if err != nil {
		return nil, err
	}

	clerkUserCacheMu.Lock()
	clerkUserCache[userID] = clerkUserCacheEntry{
		user:      user,
		expiresAt: time.Now().Add(ttl),
	}
	clerkUserCacheMu.Unlock()

	u := *user
	return &u, nil
}

func clerkUserCacheTTL() time.Duration {
	raw := strings.TrimSpace(os.Getenv("CLERK_USER_CACHE_TTL_SECONDS"))
	if raw == "" {
		return 5 * time.Minute
	}
	secs, err := time.ParseDuration(raw + "s")
	if err != nil || secs <= 0 {
		return 5 * time.Minute
	}
	return secs
}

// FromContext returns the Clerk user stored in context by ClerkMiddleware.
func FromContext(ctx context.Context) (*ClerkUser, bool) {
	u, ok := ctx.Value(clerkUserKey).(*ClerkUser)
	return u, ok
}
