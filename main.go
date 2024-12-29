package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

// Database setup
var db *sqlx.DB

// User structure
type User struct {
	ID       int    `db:"id"`
	Username string `db:"username"`
	Password string `db:"password"`
}

// JWT claims structure
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var jwtSecretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
var refreshSecretKey = []byte(os.Getenv("REFRESH_SECRET_KEY"))

// Initialize SQLite Database
func initDB() {
	var err error
	db, err = sqlx.Connect("sqlite3", "./user.db")
	if err != nil {
		log.Fatal(err)
	}
}

func createUserTable() {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	)`)
	if err != nil {
		log.Fatal(err)
	}
}

// Constants for Argon2 configuration
const (
	// Time cost (iterations)
	timeCost = 1
	// Memory cost in KB
	memoryCost = 64 * 1024
	// Parallelism factor (number of threads)
	parallelism = 4
	// Length of the resulting hash (in bytes)
	hashLength = 32
	// Salt length (in bytes)
	saltLength = 16
)

// HashPassword generates a hashed password with a unique salt using Argon2.
func hashPassword(password string) string {
	// Generate a random salt
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		log.Fatalf("Error generating random salt: %v", err)
	}

	// Generate the Argon2 hash using the password and salt
	hashed := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, parallelism, hashLength)

	// Concatenate the salt and the hash for storage
	// Format: salt + hash (both hex-encoded)
	return fmt.Sprintf("%x$%x", salt, hashed)
}

// VerifyPassword checks if the provided password matches the stored hash.
func verifyPassword(storedPassword, providedPassword string) bool {
	// Split the stored password into salt and hash components
	parts := strings.Split(storedPassword, "$")
	if len(parts) != 2 {
		log.Fatal("Invalid stored password format")
		return false
	}

	// Decode the salt and hash
	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		log.Fatalf("Error decoding salt: %v", err)
		return false
	}
	storedHash, err := hex.DecodeString(parts[1])
	if err != nil {
		log.Fatalf("Error decoding hash: %v", err)
		return false
	}

	// Hash the provided password using the same salt
	providedHash := argon2.IDKey([]byte(providedPassword), salt, timeCost, memoryCost, parallelism, hashLength)

	// Compare the stored hash with the newly computed hash
	return subtle.ConstantTimeCompare(storedHash, providedHash) == 1
}

// Generate JWT Token
func generateJWTToken(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "gin-auth",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecretKey)
}

// Generate Refresh Token
func generateRefreshToken(username string) (string, error) {
	expirationTime := time.Now().Add(7 * 24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "gin-auth-refresh",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(refreshSecretKey)
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var accessToken string

		// First, check for cookie-based token (for web frontend)
		if cookieToken, err := c.Cookie("access_token"); err == nil && cookieToken != "" {
			accessToken = cookieToken
		}

		// If no cookie, check the Authorization header (for mobile apps)
		if accessToken == "" {
			accessToken = c.GetHeader("Authorization")
			// Remove "Bearer " prefix if it's present
			if len(accessToken) > 7 && accessToken[:7] == "Bearer " {
				accessToken = accessToken[7:]
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization token is required"})
				c.Abort()
				return
			}
		}

		// Parse and validate the token
		token, err := jwt.ParseWithClaims(accessToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecretKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}

		// Validate the Issuer
		if claims, ok := token.Claims.(*Claims); ok {
			if claims.Issuer != "gin-auth" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token issuer"})
				c.Abort()
				return
			}
		}

		// Store username in context for further use
		c.Set("username", token.Claims.(*Claims).Username)
		c.Next()
	}
}

// Login handler
func login(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request"})
		return
	}

	var dbUser User
	err := db.Get(&dbUser, "SELECT id, username, password FROM users WHERE username=?", user.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "User not found"})
		return
	}

	if !verifyPassword(dbUser.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid password"})
		return
	}

	// Generate JWT and Refresh token
	token, err := generateJWTToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not create token"})
		return
	}

	refreshToken, err := generateRefreshToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not create refresh token"})
		return
	}

	// Use the helper function to check if the request is from a mobile device
	if isMobileUserAgent(c) {
		// If the request is from a mobile app, return tokens in the response body
		c.JSON(http.StatusOK, gin.H{
			"access_token":  token,
			"refresh_token": refreshToken,
		})
	} else {
		// If the request is from a web frontend, set cookies
		c.SetCookie("access_token", token, 3600, "/", "api.shibidi.war", true, true)
		c.SetCookie("refresh_token", refreshToken, 10*24*3600, "/", "api.shibidi.war", true, true)

		// Return a success message for web frontend
		c.JSON(http.StatusOK, gin.H{
			"message":       "Logged in successfully",
			"access_token":  token,
			"refresh_token": refreshToken,
		})
	}
}

func refreshToken(c *gin.Context) {
	var refreshToken string

	// Check if the request is from a web (cookies) or mobile (header)
	if cookieToken, err := c.Cookie("refresh_token"); err == nil && cookieToken != "" {
		refreshToken = cookieToken
	} else {
		// Mobile app can pass the refresh token in the Authorization header
		refreshToken = c.GetHeader("Authorization")
		// Remove "Bearer " prefix if it's present
		if len(refreshToken) > 7 && refreshToken[:7] == "Bearer " {
			refreshToken = refreshToken[7:]
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Refresh token is required"})
			return
		}
	}

	// Parse and validate the refresh token
	token, err := jwt.ParseWithClaims(refreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return refreshSecretKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid refresh token"})
		return
	}

	// Validate the Issuer
	if claims, ok := token.Claims.(*Claims); ok {
		if claims.Issuer != "gin-auth-refresh" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid refresh token issuer"})
			return
		}
	}

	claims := token.Claims.(*Claims)
	newAccessToken, err := generateJWTToken(claims.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not create new access token"})
		return
	}

	// Use the helper function to check if the request is from a mobile device
	if isMobileUserAgent(c) {
		// Return new access token in the response for mobile apps
		c.JSON(http.StatusOK, gin.H{
			"access_token": newAccessToken,
		})
	} else {
		// Set new access token in cookies for web frontend
		c.SetCookie("access_token", newAccessToken, 3600, "/", "api.shibidi.war", true, true)
	}
}

func insertTestUser() {
	var count int
	err := db.Get(&count, "SELECT COUNT(*) FROM users WHERE username = ?", "user")
	if err != nil {
		log.Fatalf("Error checking for existing user: %v", err)
	}

	// Insert the user only if they don't already exist
	if count == 0 {
		hashedPassword := hashPassword("123")
		_, err := db.Exec(`INSERT INTO users (username, password) VALUES (?, ?)`, "user", hashedPassword)
		if err != nil {
			log.Fatalf("Error inserting test user: %v", err)
		}
		fmt.Println("Test user inserted")
	} else {
		fmt.Println("Test user already exists")
	}
}

// Helper function to detect if the request is from a mobile device
func isMobileUserAgent(c *gin.Context) bool {
	userAgent := c.GetHeader("User-Agent")
	// Check for common mobile user-agent substrings
	return strings.Contains(userAgent, "Mobile") || strings.Contains(userAgent, "iPhone") || strings.Contains(userAgent, "Android")
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {
	initDB()
	createUserTable()
	insertTestUser()

	// Router and routes
	r := gin.Default()

	r.GET("/api/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, world!"})
	})
	r.POST("/api/login", login)
	r.POST("/api/refresh-token", refreshToken)

	// Authenticated routes
	auth := r.Group("/api/auth", authMiddleware())
	auth.GET("/profile", func(c *gin.Context) {
		username, _ := c.Get("username")
		c.JSON(http.StatusOK, gin.H{"username": username})
	})

	r.Run(":8080")
}
