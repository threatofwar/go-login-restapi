package handlers

import (
	"go-login-restapi/pkg/db"
	"go-login-restapi/pkg/db/models"
	"go-login-restapi/token"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Forgot Password function
func ForgotPasswordHandler(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email"})
		return
	}

	// Check email exists
	var emailRecord struct {
		UserID int `db:"user_id"`
	}

	// check if email exists
	err := db.DB.Get(&emailRecord, "SELECT user_id FROM emails WHERE email = ?", req.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email not found or invalid"})
		return
	}

	// user->hasMany->emails; retrieve user from email user_id
	var user models.User
	err = db.DB.Get(&user, "SELECT id, username, password FROM users WHERE id = ?", emailRecord.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		return
	}

	// generate a password reset token
	resetToken, err := token.GenerateResetToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate reset token"})
		return
	}

	// Store the password reset token in the users table
	_, err = db.DB.Exec("UPDATE users SET password_reset_token = ? WHERE id = ?", resetToken, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not store reset token"})
		return
	}

	// Send reset token via email
	go sendResetEmail(req.Email, resetToken)

	// Respond
	c.JSON(http.StatusOK, gin.H{"message": "Password reset email sent", "password_reset_token": resetToken})
}

// Send email function - temp can be viewed in backend console
func sendResetEmail(email, resetToken string) {
	resetLink := "https://app.shibidi.my/reset-password?token=" + resetToken
	println("Sending reset link to:", email)
	println("Reset link:", resetLink)
}
