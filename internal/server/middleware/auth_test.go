package middleware

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTGenerationAndValidation(t *testing.T) {
	secret := "test-secret-key-32-chars-long-123456"
	token, err := GenerateToken(1, "admin", "admin", secret, 2)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}
	if token == "" {
		t.Fatal("generated token is empty")
	}

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("token parsing failed: %v", err)
	}

	if claims.Username != "admin" || claims.UserID != 1 || claims.Role != "admin" {
		t.Errorf("claims mismatch: %+v", claims)
	}

	// Test expiration logic
	if claims.ExpiresAt.Time.Before(time.Now()) {
		t.Error("token should not be expired")
	}
}
