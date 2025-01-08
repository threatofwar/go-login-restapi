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
	// err := godotenv.Load()
	// if err != nil {
	// 	log.Fatal("Error loading .env file")
	// }

	ALLOWORIGINS_URL := os.Getenv("ALLOWORIGINS_URL")
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
	router.GET("/authenticated", func(c *gin.Context) {
		auth.IsAuthenticated(c.Writer, c.Request)
	})

	// routes with auth
	authGroup := router.Group("/auth", auth.AuthMiddleware())
	authGroup.GET("/profile", func(c *gin.Context) {
		username, _ := c.Get("username")

		user, err := models.GetUserWithEmails(username.(string))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch user profile"})
			return
		}

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
