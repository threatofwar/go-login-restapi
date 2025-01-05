package token

import (
	"errors"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
var refreshSecretKey = []byte(os.Getenv("REFRESH_SECRET_KEY"))
var emailVerificationSecretKey = []byte(os.Getenv("EMAIL_VERIFICATION_SECRET_KEY"))
var resetSecretKey = []byte(os.Getenv("RESET_SECRET_KEY"))

// type Claims struct {
// 	Username string `json:"username"`
// 	jwt.StandardClaims
// }

type Claims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	jwt.StandardClaims
}

// Auth token
func GenerateJWTToken(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "threatofwar-auth",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecretKey)
}

func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return token.Claims.(*Claims), nil
}

// Refresh token
func GenerateRefreshToken(username string) (string, error) {
	expirationTime := time.Now().Add(7 * 24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "threatofwar-auth-refresh",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(refreshSecretKey)
}

func ValidateRefreshToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return refreshSecretKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid refresh token")
	}
	return token.Claims.(*Claims), nil
}

// Email verification token
func GenerateVerificationToken(username, email string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour) // Token valid for 1 hour
	claims := &Claims{
		Username: username,
		Email:    email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "threatofwar-email-verification",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(emailVerificationSecretKey)
}

func ValidateVerificationToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return emailVerificationSecretKey, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid verification token")
	}
	return token.Claims.(*Claims), nil
}

// Password reset token
func GenerateResetToken(username string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour) // Token valid for 1 hour
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "threatofwar-reset",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(resetSecretKey)
}

func ValidateResetToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return resetSecretKey, nil
	})
	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired reset token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", errors.New("could not parse token claims")
	}

	return claims.Username, nil
}
