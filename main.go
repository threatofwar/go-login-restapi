package main

import (
	"golang.org/x/crypto/argon2"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/jmoiron/sqlx"
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
	salt := []byte("somesalt") // You should use a unique salt for each user
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

// Middleware to validate JWT Token
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is required"})
			c.Abort()
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
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

	c.JSON(http.StatusOK, gin.H{
		"access_token":  token,
		"refresh_token": refreshToken,
	})
}

// Refresh token handler
func refreshToken(c *gin.Context) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request"})
		return
	}

	token, err := jwt.ParseWithClaims(request.RefreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
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

	c.JSON(http.StatusOK, gin.H{
		"access_token": newAccessToken,
	})
}

func insertTestUser() {
	hashedPassword := hashPassword("testpassword") // Hash a test password
	_, err := db.Exec(`INSERT INTO users (username, password) VALUES (?, ?)`, "testuser", hashedPassword)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Test user inserted")
}

func main() {
	// Initialize and create table
	initDB()
	createUserTable()
	insertTestUser()

	// Setup router and routes
	r := gin.Default()

	r.POST("/login", login)
	r.POST("/refresh-token", refreshToken)

	// Authenticated routes
	auth := r.Group("/auth", authMiddleware())
	auth.GET("/profile", func(c *gin.Context) {
		username, _ := c.Get("username")
		c.JSON(http.StatusOK, gin.H{"username": username})
	})

	r.Run(":8080")
}

