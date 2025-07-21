package route

import (
	"auth-service/internal/controller"
	"net/http"

	"github.com/gin-gonic/gin"
)

type router struct {
	router *gin.Engine
}

type ControllersConfig struct {
	Auth *controller.AuthController
	Ads  *controller.AdsController
}

func NewRouter(cfg ControllersConfig) *router {
	r := router{
		router: gin.Default(),
	}

	authPrivate := r.router.Group("/api")
	authPrivate.Use(cfg.Auth.ValidateToken)
	{
		authPrivate.POST("/logout", cfg.Auth.Logout)
		authPrivate.POST("/token/refresh", cfg.Auth.Refresh)
		authPrivate.POST("/secret/:id", cfg.Auth.TakeTokens)
	}

	authPublic := r.router.Group("/api")
	{
		authPublic.POST("/signup", cfg.Auth.SignUp)
		authPublic.POST("/login", cfg.Auth.Login)
	}

	ads := r.router.Group("/api/ads")
	{
		ads.GET("/", cfg.Auth.ValidateTokenOptional, cfg.Ads.GetAll)
		ads.POST("/create", cfg.Auth.ValidateToken, cfg.Ads.Create)
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
