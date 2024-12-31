package main

import (
	"log"
	"net/http"
	"os"

	"go-login-restapi/auth"
	"go-login-restapi/pkg/db"
	"go-login-restapi/pkg/db/models"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize database
	db.InitDB()
	db.CreateTables()
	models.InsertTestUser()
	models.InsertTestUserEmail()

	router := gin.Default()

	// routes without auth
	router.GET("/api/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, world!"})
	})
	router.POST("/api/login", auth.Login)
	router.POST("/api/refresh-token", auth.RefreshToken)
	router.POST("/api/register", auth.Register)

	// routes with auth
	authGroup := router.Group("/api/auth", auth.AuthMiddleware())
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
