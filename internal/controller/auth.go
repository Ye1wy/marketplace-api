package controller

import (
	"auth-service/internal/mapper"
	"auth-service/internal/model/domain"
	"auth-service/internal/model/dto"
	"auth-service/internal/service"
	"auth-service/pkg/logger"
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthService interface {
	SignUp(ctx context.Context, user domain.User) error
	Login(ctx context.Context, user domain.User) (*domain.Token, error)
	Logout(ctx context.Context, token domain.Token) error
	Refresh(ctx context.Context, token domain.Token) (*domain.Token, error)
	Secret(ctx context.Context, id uuid.UUID, ip string) (*domain.Token, error)
}

type AuthController struct {
	*BaseController
	service AuthService
}

func NewAuth(service AuthService /* secretKey string*/, logger *logger.Logger) *AuthController {
	ctrl := NewBaseController(logger)
	return &AuthController{
		ctrl,
		service,
	}
}

func (ctrl *AuthController) SignUp(c *gin.Context) {
	op := "controller.auth.Register"
	var inputUser dto.Register

	if err := c.ShouldBind(&inputUser); err != nil {
		ctrl.logger.Error("Failed bind data", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"err": "aboba"})
		return
	}

	user := mapper.RegisterToDomain(inputUser)

	err := ctrl.service.SignUp(c.Request.Context(), user)
	if errors.Is(err, service.ErrNoContent) {
		ctrl.logger.Error("No content in all or one+ field input data", "data", user, "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"error": user})
		return
	}

	if err != nil {
		ctrl.logger.Error("Failed in sign up", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": "something wrong with service"})
		return
	}

	c.Status(http.StatusCreated)
	c.Redirect(http.StatusMovedPermanently, "/login")
}

func (ctrl *AuthController) Login(c *gin.Context) {
	op := "controller.auth.Login"
	var inputData dto.LoginRequest

	if err := c.ShouldBind(&inputData); err != nil {
		ctrl.logger.Error("Failed bind data", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"msg": "Invalid payload"})
		return
	}

	user := mapper.LoginToDomain(inputData)
	user.Ip = c.ClientIP()

	tokens, err := ctrl.service.Login(c.Request.Context(), user)
	if errors.Is(err, service.ErrIncorrectUsernameOrPassword) {
		ctrl.responce(c, http.StatusUnauthorized, gin.H{"massage": "incorrect payload"})
		return
	}

	if err != nil {
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": "server error"})
		return
	}

	dto := mapper.TokenToDto(*tokens)

	ctrl.responce(c, http.StatusOK, dto)
}

func (ctrl *AuthController) Logout(c *gin.Context) {
	op := "controller.auth.Logout"

	var inputTokens dto.Token
	if err := c.ShouldBind(&inputTokens); err != nil {
		ctrl.responce(c, http.StatusUnauthorized, gin.H{"401": "Unauthorized"})
		return
	}

	tokens := mapper.TokenToDomain(inputTokens)

	if err := ctrl.service.Logout(c.Request.Context(), tokens); err != nil {
		ctrl.logger.Error("Service error", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": "server is dead"})
		return
	}

	ctrl.responce(c, http.StatusResetContent, gin.H{})
}

func (ctrl *AuthController) Refresh(c *gin.Context) {
	op := "controller.auth.Refresh"

	var inputTokens dto.Token
	if err := c.ShouldBind(&inputTokens); err != nil {
		ctrl.logger.Warn("User don't have tokens or something wrong with bind", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusUnauthorized, gin.H{"401": "UNnauthorized"})
		return
	}

	tokens := mapper.TokenToDomain(inputTokens)
	ip := c.ClientIP()
	tokens.Ip = ip

	newTokens, err := ctrl.service.Refresh(c.Request.Context(), tokens)
	if errors.Is(err, service.ErrInvalidToken) || errors.Is(err, service.ErrNoContent) || errors.Is(err, service.ErrNewIp) {
		ctrl.responce(c, http.StatusUnauthorized, gin.H{"401": "Unauthorized"})
		return
	}

	if err != nil {
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": "server is dead"})
		return
	}

	dto := mapper.TokenToDto(*newTokens)

	ctrl.responce(c, http.StatusOK, dto)
}

func (ctrl *AuthController) TakeTokens(c *gin.Context) {
	op := "controller.auth.TakeTokens"

	idStr := c.Param("id")

	id := uuid.MustParse(idStr)

	ip := c.ClientIP()

	tokens, err := ctrl.service.Secret(c.Request.Context(), id, ip)
	if err != nil {
		ctrl.logger.Error("Error with create secret tokens", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": "server is dead"})
		return
	}

	dto := mapper.TokenToDto(*tokens)
	ctrl.responce(c, http.StatusOK, dto)
}

// func (ctrl *AuthController) AuthentificateMiddleware(c *gin.Context) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		tokenStr := c.Request.Header.Get("access_token")
// 		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
// 			return ctrl.secretKey, nil
// 		})

// 		if err != nil || !token.Valid {
// 			ctrl.responce(c, http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
// 			c.Abort()
// 			return
// 		}

// 		c.Next()
// 	}
// }
