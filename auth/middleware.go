package auth

import (
	"net/http"
	"strings"

	"go-login-restapi/token"

	"github.com/gin-gonic/gin"
)

// handles token authentication
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var accessToken string

		// Retrieve token from cookie or header
		if cookieToken, err := c.Cookie("access_token"); err == nil && cookieToken != "" {
			accessToken = cookieToken
		} else {
			accessToken = c.GetHeader("Authorization")
			if len(accessToken) > 7 && strings.HasPrefix(accessToken, "Bearer ") {
				accessToken = accessToken[7:]
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization token is required"})
				c.Abort()
				return
			}
		}

		claims, err := token.ValidateToken(accessToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}
