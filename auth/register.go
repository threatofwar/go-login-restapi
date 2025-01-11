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

	// check username exists
	if userExists(input.Username) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already taken"})
		return
	}

	// password hash
	hashedPassword := hash.HashPassword(input.Password)

	// create user object
	user := models.User{
		Username: input.Username,
		Password: hashedPassword,
	}

	// db begin
	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to start transaction"})
		return
	}

	// save object
	if err := user.Save(tx); err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to register user"})
		return
	}

	var emailVerificationTokens []map[string]string

	// user->hasMany->emails loops
	for _, email := range input.Emails {
		emailObj := models.Email{
			UserID: user.ID,
			Email:  email,
		}

		// save object
		if err := emailObj.Save(tx); err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to register email"})
			return
		}

		// generate token
		verificationToken, err := token.GenerateVerificationToken(tx, user.Username, email)
		log.Printf("username: %s", user.Username)
		log.Printf("email: %s", email)
		if err != nil {
			log.Printf("Error generating verification token for email %s: %v", email, err)
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate verification token"})
			return
		}

		emailVerificationTokens = append(emailVerificationTokens, map[string]string{
			"email":              email,
			"verification_token": verificationToken,
		})
	}

	// db end
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// output
	c.JSON(http.StatusOK, gin.H{
		"message": "User registered successfully with emails",
		"emails":  emailVerificationTokens,
	})
}

// check if user exists
func userExists(username string) bool {
	var count int
	err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
	if err != nil {
		log.Println("Error checking username existence:", err)
		return false
	}
	return count > 0
}
