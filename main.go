package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// JWTMiddleware handles JWT authentication with dynamic JWK cache refreshing.
type JWTMiddleware struct {
	cache   *jwk.Cache
	jwksURL string
}

// NewJWTMiddleware initializes a new JWTMiddleware with a jwk.Cache.
func NewJWTMiddleware(ctx context.Context, jwksURL string, minRefreshInterval time.Duration) (*JWTMiddleware, error) {
	cache := jwk.NewCache(ctx)

	// Register the JWKS URL with auto-refresh options
	err := cache.Register(jwksURL,
		jwk.WithMinInterval(minRefreshInterval),
		jwk.WithRefreshInterval(1*time.Hour), // Fallback TTL
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
	}

	// Perform initial fetch to populate the cache and verify the URL works
	_, err = cache.Refresh(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to perform initial JWKS fetch: %w", err)
	}

	return &JWTMiddleware{
		cache:   cache,
		jwksURL: jwksURL,
	}, nil
}

// Handler returns an HTTP middleware handler.
func (m *JWTMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]
		ctx := r.Context()

		// Retrieve the keyset from the cache
		keyset, err := m.cache.Get(ctx, m.jwksURL)
		if err != nil {
			http.Error(w, "Failed to retrieve JWK set", http.StatusInternalServerError)
			return
		}

		// Extract the kid from the token headers without verification
		msg, err := jws.Parse([]byte(tokenString))
		if err != nil {
			http.Error(w, "Invalid token format", http.StatusUnauthorized)
			return
		}

		var kid string
		if len(msg.Signatures()) > 0 {
			kid = msg.Signatures()[0].ProtectedHeaders().KeyID()
		}

		// If the kid is not in the current keyset, attempt to refresh the cache
		if kid != "" {
			if _, hasKey := keyset.LookupKeyID(kid); !hasKey {
				// Force refresh the cache (respecting MinInterval)
				if updatedKeyset, refreshErr := m.cache.Refresh(ctx, m.jwksURL); refreshErr == nil {
					keyset = updatedKeyset
				}
			}
		}

		// Parse and verify the token
		token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keyset))
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		// Store the token in the request context
		ctx = context.WithValue(ctx, "token", token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func main() {
	fmt.Println("Hello, Bounty Hunter!")
}
