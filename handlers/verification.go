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

	claims, err := token.ValidateVerificationToken(request.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid verification token"})
		return
	}

	err = models.UpdateEmailVerificationStatus(claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update email verification status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Email verification successful",
		"email":    claims.Email,
		"username": claims.Username,
	})
}
