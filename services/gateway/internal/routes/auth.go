package routes

import "github.com/gin-gonic/gin"

func AuthRoutes(group *gin.RouterGroup) {
	group.POST("/login")
	group.POST("/register")
	group.POST("/refresh")
}
