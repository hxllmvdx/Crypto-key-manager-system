package middleware

import (
	jwtManager "github.com/hxllmvdx/Crypto-key-management-system/services/gateway/internal/jwt"
	"strings"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware(m jwtManager.TokenManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "Authorization header missing"})
			return
		}

		if len(header) < 7 || !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid authorization header"})
			return
		}

		tokenString := strings.TrimPrefix(header, "Bearer ")

		claims, err := m.ParseAccessToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token"})
			return
		}

		c.Set("user_id", claims.Subject)
		c.Next()
	}
}
