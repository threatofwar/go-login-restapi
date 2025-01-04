package auth

import (
	"log"
	"net/http"

	"go-login-restapi/hash"
	"go-login-restapi/pkg/db"
	"go-login-restapi/pkg/db/models"
	"go-login-restapi/token"

	"github.com/gin-gonic/gin"
)

// Register new user function
func Register(c *gin.Context) {
	var input struct {
		Username string   `json:"username" binding:"required"`
		Password string   `json:"password" binding:"required"`
		Emails   []string `json:"emails" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if userExists(input.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already taken"})
		return
	}

	hashedPassword := hash.HashPassword(input.Password)

	user := models.User{
		Username: input.Username,
		Password: hashedPassword,
	}

	if err := user.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to register user"})
		return
	}

	var err error
	var verificationToken string

	for _, email := range input.Emails {
		emailObj := models.Email{
			UserID: user.ID,
			Email:  email,
		}

		if err := emailObj.Save(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to register email"})
			return
		}

		// Generate a verification token for the email
		verificationToken, err = token.GenerateVerificationToken(user.Username, email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate verification token"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":            "User registered successfully with emails",
		"verification_token": verificationToken,
	})
}

func userExists(username string) bool {
	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		log.Println("Error checking username existence:", err)
		return false
	}
	return count > 0
}
