package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
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

var jwtSecretKey = []byte("your-secret-key")
var refreshSecretKey = []byte("your-refresh-secret-key")

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

// Hash Password using Argon2
func hashPassword(password string) string {
	salt := []byte("somesalt")
	hashed := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return fmt.Sprintf("%x", hashed)
}

// Verify Password
func verifyPassword(storedPassword, providedPassword string) bool {
	return storedPassword == hashPassword(providedPassword)
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
		accessToken, err := c.Cookie("access_token")
		if err != nil || accessToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Access token is required"})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(accessToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecretKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}

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

	// Set cookies (gin)
	c.SetCookie("access_token", token, 3600, "/", "ddapp.shibidi.war", true, true)
	c.SetCookie("refresh_token", refreshToken, 10*24*3600, "/", "ddapp.shibidi.war", true, true)

	// if manually set cookies
	// c.Header("Set-Cookie", "access_token="+token+"; Max-Age=3600; Path=/; Domain=.shibidi.war; Secure; HttpOnly; SameSite=None")
	// c.Header("Set-Cookie", "refresh_token="+refreshToken+"; Max-Age=604800; Path=/; Domain=api.shibidi.war; Secure; HttpOnly; SameSite=None")

	// Return response with tokens (optional: maybe to add for mobile access)
	c.JSON(http.StatusOK, gin.H{
		"access_token":  token,
		"refresh_token": refreshToken,
	})
}

func refreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil || refreshToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Refresh token is required"})
		return
	}

	token, err := jwt.ParseWithClaims(refreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return refreshSecretKey, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid refresh token"})
		return
	}

	claims := token.Claims.(*Claims)
	newAccessToken, err := generateJWTToken(claims.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not create new access token"})
		return
	}

	// Set new access token in cookies
	c.SetCookie("access_token", newAccessToken, 3600, "/", "", false, true) // 1 hour expiry, HttpOnly

	c.JSON(http.StatusOK, gin.H{
		"access_token": newAccessToken,
	})
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
