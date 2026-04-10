package routes

import "github.com/gin-gonic/gin"

func ApiRoutes(group *gin.RouterGroup) {
	group.GET("/keys")
	group.GET("/keys/:id")
	group.POST("/keys")
	group.POST("/keys/:id/rotate")
	group.POST("/keys/:id/restore")
	group.DELETE("/keys/:id")
	group.DELETE("/keys/:id/purge")

	group.POST("/encrypt")
	group.POST("/decrypt")
}
