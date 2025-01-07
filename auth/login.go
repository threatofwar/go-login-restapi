package auth

import (
	"go-login-restapi/hash"
	"go-login-restapi/pkg/db"
	"go-login-restapi/pkg/db/models"
	"go-login-restapi/token"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

var COOKIES_FQDN = os.Getenv("COOKIES_FQDN")
var HEADER_USERAGENT_KEY string

func Login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var user models.User

	isEmail := strings.Contains(req.Username, "@")

	if isEmail {
		// Login using email address
		err := db.DB.Get(&user, `
			SELECT users.id, users.username, users.password 
			FROM users 
			JOIN emails ON users.id = emails.user_id 
			WHERE emails.email = ?`, req.Username)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
			return
		}
	} else {
		// Login using username
		err := db.DB.Get(&user, "SELECT id, username, password FROM users WHERE username = ?", req.Username)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}
	}

	if !hash.VerifyPassword(user.Password, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username/email or password"})
		return
	}

	accessToken, err := token.GenerateJWTToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate access token"})
		return
	}

	refreshToken, err := token.GenerateRefreshToken(user.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate refresh token"})
		return
	}

	if isMobileUserAgent(c) {
		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	} else {
		// gin set cookies
		// c.SetCookie("access_token", accessToken, 3600, "/", COOKIES_FQDN, true, true)
		// c.SetCookie("refresh_token", refreshToken, 10*24*3600, "/", COOKIES_FQDN, true, true)

		// manually set cookies
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "access_token",
			Value:    accessToken,
			Path:     "/",
			Domain:   os.Getenv("COOKIES_FQDN"),
			Expires:  time.Now().Add(3600 * time.Second),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
		})

		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Path:     "/",
			Domain:   os.Getenv("COOKIES_FQDN"),
			Expires:  time.Now().Add(10 * 24 * time.Hour),
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteNoneMode,
		})

		c.JSON(http.StatusOK, gin.H{
			"message": "Logged in successfully!",
		})
	}
}

func RefreshToken(c *gin.Context) {
	var refreshToken string

	if cookieToken, err := c.Cookie("refresh_token"); err == nil && cookieToken != "" {
		refreshToken = cookieToken
	} else {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		refreshToken = req.RefreshToken
	}

	claims, err := token.ValidateRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	if claims.Issuer != "threatofwar-auth-refresh" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token issuer"})
		return
	}

	accessToken, err := token.GenerateJWTToken(claims.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create new access token"})
		return
	}

	if isMobileUserAgent(c) {
		c.JSON(http.StatusOK, gin.H{
			"access_token": accessToken,
		})
	} else {
		c.SetCookie("access_token", accessToken, 3600, "/", COOKIES_FQDN, true, true)
		c.JSON(http.StatusOK, gin.H{
			"message": "Access token refreshed success!",
			// "access_token": accessToken,
		})
	}
}

func isMobileUserAgent(c *gin.Context) bool {
	HEADER_USERAGENT_KEY = os.Getenv("HEADER_USERAGENT_KEY")
	userAgent := c.GetHeader("User-Agent")
	return strings.Contains(userAgent, HEADER_USERAGENT_KEY)
}

func isEmail(input string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(input)
}

func IsAuthenticated(w http.ResponseWriter, r *http.Request) {
	// Get the token from cookies
	cookie, err := r.Cookie("access_token")
	if err != nil || cookie.Value == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// validate token
	claims, err := token.ValidateToken(cookie.Value)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"authenticated": true, "username": "` + claims.Username + `"}`))
}