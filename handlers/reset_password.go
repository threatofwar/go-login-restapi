package handlers

import (
	"go-login-restapi/hash"
	"go-login-restapi/pkg/db"
	"go-login-restapi/pkg/db/models"
	"go-login-restapi/token"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Password Reset
func ResetPasswordHandler(c *gin.Context) {
	var req struct {
		Token       string `json:"password_reset_token"`
		NewPassword string `json:"new_password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// validate password_reset_token.
	username, err := token.ValidateResetToken(req.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired reset token"})
		return
	}

	var user models.User
	err = db.DB.Get(&user, "SELECT id, username, password, password_reset_token, password_reset_token_used FROM users WHERE username = ?", username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Ensure reset token exists in DB and matches the requested token
	if user.PasswordResetToken == nil || *user.PasswordResetToken != req.Token {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid reset token"})
		return
	}

	if user.PasswordResetTokenUsed {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Reset token has already been used"})
		return
	}

	hashedPassword := hash.HashPassword(req.NewPassword)

	// Update new password
	_, err = db.DB.Exec("UPDATE users SET password = ? WHERE username = ?", hashedPassword, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not reset password"})
		return
	}

	// Mark the password reset token as used by updating the 'password_reset_token_used' field
	_, err = db.DB.Exec("UPDATE users SET password_reset_token_used = TRUE WHERE username = ?", username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not mark token as used"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}
