package route

import (
	"auth-service/internal/controller"
	"net/http"

	"github.com/gin-gonic/gin"
)

type router struct {
	router *gin.Engine
}

func NewRouter(auth *controller.AuthController) *router {
	r := router{
		router: gin.Default(),
	}

	authGroup := r.router.Group("/api/v1")
	{
		authGroup.POST("/signup", auth.SignUp)
		authGroup.POST("/login", auth.Login)
		authGroup.POST("/logout", auth.Logout)
		authGroup.POST("/token/refresh", auth.Refresh)
		authGroup.POST("/secret/:id", auth.TakeTokens)
	}

	r.router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"massage": "pong",
		})
	})

	return &r
}

func (r *router) Run(addr ...string) error {
	return r.router.Run(addr...)
}
