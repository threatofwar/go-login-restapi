package handlers

import (
	"go-login-restapi/pkg/db"
	"go-login-restapi/pkg/services"
	"go-login-restapi/token"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GenerateVerificationTokenHandler(c *gin.Context) {
	var request struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to start transaction"})
		return
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username and valid email are required"})
		return
	}

	verificationToken, err := token.GenerateVerificationToken(tx, request.Username, request.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate verification token"})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
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

	email, err := services.GetEmailByToken(request.Token, claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve email with token"})
		return
	}

	if email.Verified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email has already been verified"})
		return
	}

	if email == nil || (email.VerificationToken != nil && *email.VerificationToken != request.Token) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired verification token"})
		return
	}

	err = services.UpdateEmailVerificationStatus(claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update email verification status"})
		return
	}

	// output
	c.JSON(http.StatusOK, gin.H{
		"message":  "Email verification successful",
		"email":    claims.Email,
		"username": claims.Username,
	})
}
