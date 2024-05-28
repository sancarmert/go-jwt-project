package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/sancarmert/go-jwt-project/controllers"
	"github.com/sancarmert/go-jwt-project/middleware"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controllers.GetUsers())
	incomingRoutes.GET("/users/id", controllers.GetUser())
}
