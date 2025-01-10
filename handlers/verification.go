package handlers

import (
	"go-login-restapi/pkg/db/models"
	"go-login-restapi/token"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GenerateVerificationTokenHandler(c *gin.Context) {
	var request struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and valid email are required"})
		return
	}

	verificationToken, err := token.GenerateVerificationToken(request.Username, request.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate verification token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"verification_token": verificationToken})
}

func VerifyEmailHandler(c *gin.Context) {
	var request struct {
		Token string `json:"verification_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Verification token is required"})
		return
	}

	// Validate the token
	claims, err := token.ValidateVerificationToken(request.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid verification token"})
		return
	}

	// Fetch the email from the database by the verification token and email
	email, err := models.GetEmailByToken(request.Token, claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve email with token"})
		return
	}

	if email.Verified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email has already been verified"})
		return
	}

	// If no email is found or the token does not match, return an error
	if email == nil || (email.VerificationToken != nil && *email.VerificationToken != request.Token) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired verification token"})
		return
	}

	// Update the email verification status
	err = models.UpdateEmailVerificationStatus(claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update email verification status"})
		return
	}

	// Return success message
	c.JSON(http.StatusOK, gin.H{
		"message":  "Email verification successful",
		"email":    claims.Email,
		"username": claims.Username,
	})
}
