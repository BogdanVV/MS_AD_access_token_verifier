package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"test_auth/models"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// TODO: rename if more endpoints are added
func MainHandler(c *gin.Context) {
	authHeader := c.GetHeader("authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
		return
	}

	authHeaderChunks := strings.Split(authHeader, " ")
	if len(authHeaderChunks) != 2 || authHeaderChunks[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "heroviy header"})
		return
	}

	tokenString := authHeaderChunks[1]
	var claims models.MSClaims
	unverifiedToken, _ := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return jwt.ParseRSAPublicKeyFromPEM([]byte("qwe"))
	})

	res, err := http.Get("https://login.microsoftonline.com/common/.well-known/openid-configuration ")
	if err != nil {
		c.JSON(http.StatusInternalServerError, "failed to get openid-config from MS API")
		return
	}
	var jwksUriStruct struct {
		JwksUri string `json:"jwks_uri"`
	}
	json.NewDecoder(res.Body).Decode(&jwksUriStruct)

	res, err = http.Get(jwksUriStruct.JwksUri)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "failed to get the list of keys from MS API")
		return
	}
	var keysStruct struct {
		Keys []models.Key `json:"keys"`
	}
	json.NewDecoder(res.Body).Decode(&keysStruct)

	var wantedEl models.Key
	kid := unverifiedToken.Header["kid"].(string)
	for _, key := range keysStruct.Keys {
		if key.Kid == kid {
			wantedEl = models.Key{
				Kid: kid,
				X5c: key.X5c,
			}
		}
	}
	if wantedEl.X5c == nil || len(wantedEl.X5c) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get public key from MS API"})
		return
	}

	tokenSecret := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", wantedEl.X5c[0])

	var newClaims models.MSClaims
	verifiedToken, err := jwt.ParseWithClaims(tokenString, &newClaims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return jwt.ParseRSAPublicKeyFromPEM([]byte(tokenSecret))
	})

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error(), "tokenString": tokenString})
		return
	}
	if !verifiedToken.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token did not pass validation"})
		return
	}

	azureAdClientId := os.Getenv("AZURE_AD_CLIENT_ID")
	azureAdTenantId := os.Getenv("AZURE_AD_TENANT_ID")
	if newClaims.Aud != fmt.Sprintf("api://%s", azureAdClientId) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "wrong audience"})
		return
	}
	if newClaims.Iss != fmt.Sprintf("https://sts.windows.net/%s/", azureAdTenantId) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "wrong issuer"})
		return
	}
	if int64(newClaims.Exp) < time.Now().Unix() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "outdated"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}
