package controller

import (
	"auth-service/pkg/logger"

	"github.com/gin-gonic/gin"
)

type BaseController struct {
	logger *logger.Logger
}

func NewBaseController(logger *logger.Logger) *BaseController {
	return &BaseController{
		logger: logger,
	}
}

func (bc *BaseController) responce(c *gin.Context, code int, obj any) {
	switch c.GetHeader("Accept") {
	case "application/xml":
		c.XML(code, obj)
	default:
		c.JSON(code, obj)
	}
}
