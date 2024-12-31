package auth

import (
	"net/http"

	"go-login-restapi/hash"
	"go-login-restapi/pkg/db/models"

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

	hashedPassword := hash.HashPassword(input.Password)

	user := models.User{
		Username: input.Username,
		Password: hashedPassword,
	}

	if err := user.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to register user"})
		return
	}

	for _, email := range input.Emails {
		emailObj := models.Email{
			UserID: user.ID, // created userid
			Email:  email,
		}

		if err := emailObj.Save(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to register email"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully with emails"})
}
