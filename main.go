package main

import (
	"net/http"
	"os"
	"strings"

	"go-login-restapi/auth"
	"go-login-restapi/handlers"
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
	// authentication route
	router.POST("/login", auth.Login)
	router.POST("/refresh-token", auth.RefreshToken)
	router.GET("/authenticated", func(c *gin.Context) {
		auth.IsAuthenticated(c.Writer, c.Request)
	})

	// register new user route
	router.POST("/register", auth.Register)
	router.POST("/generate-verification-token", handlers.GenerateVerificationTokenHandler)
	router.POST("/verify-email", handlers.VerifyEmailHandler)

	// password reset routes
	router.POST("/forgot-password", handlers.ForgotPasswordHandler)
	router.POST("/reset-password", handlers.ResetPasswordHandler)

	// routes with auth
	authGroup := router.Group("/auth", auth.AuthMiddleware())
	authGroup.GET("/profile", func(c *gin.Context) {
		username, exists := c.Get("username")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		user, err := models.GetUser(username.(string), true)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not fetch user profile"})
			return
		}

		emailDetails := []gin.H{}
		for _, email := range user.Emails {
			emailDetails = append(emailDetails, gin.H{
				"id":                 email.ID,
				"user_id":            email.UserID,
				"email":              email.Email,
				"verified":           email.Verified,
				"verification_token": email.VerificationToken,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"id":                        user.ID,
			"username":                  user.Username,
			"password":                  user.Password,
			"password_reset_token":      user.PasswordResetToken,
			"password_reset_token_used": user.PasswordResetTokenUsed,
			"emails":                    emailDetails,
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	router.Run(":" + port)
}
