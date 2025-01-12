package auth

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

func Logout(c *gin.Context) {
	// Delete cookies or tokens
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Expires:  time.Unix(0, 0), // Expire the cookie immediately
		Path:     "/",
		Domain:   os.Getenv("COOKIES_FQDN"),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})

	// Clear refresh_token cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Unix(0, 0), // Expire the cookie immediately
		Path:     "/",
		Domain:   os.Getenv("COOKIES_FQDN"),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})

	// c.String(http.StatusOK, "Logout successful")

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully!",
	})
}
