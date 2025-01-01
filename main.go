package main

import (
	"net/http"
	"os"
	"strings"

	"go-login-restapi/auth"
	"go-login-restapi/pkg/db"
	"go-login-restapi/pkg/db/models"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// load .env file
	// err := godotenv.Load()
	// if err != nil {
	// 	log.Fatal("Error loading .env file")
	// }
	ALLOWORIGINS_URL := os.Getenv("ALLOWORIGINS_URL")

	// If you need to support multiple origins, split by commas
	allowedOrigins := strings.Split(ALLOWORIGINS_URL, ",")

	// Initialize database
	db.InitDB()
	db.CreateTables()
	models.InsertTestUser()
	models.InsertTestUserEmail()

	router := gin.Default()

	// CORS config
	router.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		ExposeHeaders:    []string{},
		AllowCredentials: true,
		MaxAge:           12 * 3600,
	}))

	// routes without auth
	router.GET("/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, world!"})
	})
	router.POST("/login", auth.Login)
	router.POST("/refresh-token", auth.RefreshToken)
	router.POST("/register", auth.Register)
	router.GET("/authenticated", func(c *gin.Context) {
		// Wrap the original IsAuthenticated handler with Gin context
		auth.IsAuthenticated(c.Writer, c.Request)
	})

	// routes with auth
	authGroup := router.Group("/auth", auth.AuthMiddleware())
	// authGroup.GET("/profile", func(c *gin.Context) {
	// 	username, _ := c.Get("username")
	// 	c.JSON(http.StatusOK, gin.H{"username": username})
	// })
	authGroup.GET("/profile", func(c *gin.Context) {
		// Get the username from the context (you may need to replace this with your actual method of getting the username)
		username, _ := c.Get("username")

		// Retrieve the user with their emails
		user, err := models.GetUserWithEmails(username.(string)) // Assuming username is a string
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch user profile"})
			return
		}

		// Respond with the user's profile (including their emails)
		c.JSON(http.StatusOK, gin.H{
			"username": user.Username,
			"emails":   user.Emails,
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	router.Run(":" + port)
}
