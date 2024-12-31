package auth

import (
	"log"
	"net/http"

	"go-login-restapi/hash"
	"go-login-restapi/pkg/db"
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

	// Bind JSON input to the struct
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Check if the username already exists
	if userExists(input.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already taken"})
		return
	}

	// Hash the password before saving it
	hashedPassword := hash.HashPassword(input.Password)

	// Create the user object
	user := models.User{
		Username: input.Username,
		Password: hashedPassword,
	}

	// Save the user to the database
	if err := user.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to register user"})
		return
	}

	// After the user is created, register the emails
	for _, email := range input.Emails {
		emailObj := models.Email{
			UserID: user.ID, // Assign the created user ID
			Email:  email,
		}

		// Save each email to the database
		if err := emailObj.Save(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to register email"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully with emails"})
}

// userExists checks if the username already exists in the database
func userExists(username string) bool {
	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		log.Println("Error checking username existence:", err)
		return false
	}
	return count > 0
}
