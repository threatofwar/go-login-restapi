package handlers

import (
	"go-login-restapi/pkg/services"
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

	emailRecord, err := services.FindEmailByAddress(req.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email not found or invalid"})
		return
	}

	user, err := services.FindUserByID(emailRecord.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		return
	}

	resetToken, err := token.GenerateResetToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate reset token"})
		return
	}

	if err := services.StorePasswordResetToken(user.ID, resetToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not store reset token"})
		return
	}

	go sendResetEmail(req.Email, resetToken)

	// output
	c.JSON(http.StatusOK, gin.H{"message": "Password reset email sent", "password_reset_token": resetToken})
}

// Send email function - temp can be viewed in backend console
func sendResetEmail(email, resetToken string) {
	resetLink := "https://app.shibidi.my/reset-password?token=" + resetToken
	println("Sending reset link to:", email)
	println("Reset link:", resetLink)
}
