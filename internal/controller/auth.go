package controller

import (
	apie "auth-service/internal/errors"
	"auth-service/internal/mapper"
	"auth-service/internal/model/domain"
	"auth-service/internal/model/dto"
	"auth-service/pkg/logger"
	"context"
	"errors"
	"fmt"
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
	ValidateToken(ctx context.Context, accessToken string) (*domain.AccessTokenPayload, error)
}

type AuthController struct {
	*BaseController
	service AuthService
}

func NewAuth(service AuthService, logger *logger.Logger) *AuthController {
	ctrl := NewBaseController(logger)
	return &AuthController{
		ctrl,
		service,
	}
}

// SignUp godoc
//
//	@Summary		Sign up
//	@Description	This endpoint logs you into the system
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			username	query	string	true	"your username"
//	@Param			password	query	string	true	"your password"
//	@Param			email		query	string	true	"your email"
//	@Success		201
//	@Failure		400	{object}	dto.Massage
//	@Failure		500	{object}	dto.Massage
//	@Router			/api/signup [post]
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
	if errors.Is(err, apie.ErrNoContent) {
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
}

// Login godoc
//
//	@Summary		login into system
//	@Description	This endpoint provides access to parts of the system
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			username	query		string	true	"your username"
//	@Param			password	query		string	true	"your password"
//	@Success		200			{object}	dto.Massage
//	@Failure		400			{object}	dto.Massage
//	@Failure		401			{object}	dto.Massage
//	@Failure		500			{object}	dto.Massage
//	@Router			/api/login [post]
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

	if err != nil {
		if errors.Is(err, apie.ErrIncorrectUsernameOrPassword) {
			ctrl.logger.Warn("Invalid payload", logger.Err(err), "op", op)
			ctrl.responce(c, http.StatusUnauthorized, gin.H{"massage": "incorrect payload"})
			return
		}

		if errors.Is(err, apie.ErrUserNotFound) {
			ctrl.logger.Warn("User not found", logger.Err(err), "op", op)
			ctrl.responce(c, http.StatusUnauthorized, gin.H{"massage": "invalid username/email or password"})
			return
		}

		ctrl.logger.Error("Failed to login", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": "server error"})
		return
	}

	dto := mapper.TokenToDto(*tokens)
	c.Writer.Header().Set("access_token", dto.Access)
	c.Writer.Header().Set("refresh_token", dto.Refresh)
	hello := fmt.Sprintf("Hello Mr. %s", inputData.Username)
	ctrl.responce(c, http.StatusOK, gin.H{"massage": hello})
}

// Logout godoc
//
//	@Summary		logout from system
//	@Description	this endpoint prevents access to parts of the system under your session
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			access_token	header		string	true	"access token"
//	@Param			refresh_token	header		string	true	"refresh token"
//	@Success		205				{object}	dto.Massage
//	@Failure		400				{object}	dto.Massage
//	@Failure		401				{object}	dto.Massage
//	@Failure		500				{object}	dto.Massage
//	@Router			/api/logout [post]
func (ctrl *AuthController) Logout(c *gin.Context) {
	op := "controller.auth.Logout"

	accessToken := c.Request.Header.Get("access_token")
	refreshToken := c.Request.Header.Get("refresh_token")
	inputTokens := dto.Token{
		Access:  accessToken,
		Refresh: refreshToken,
	}
	tokens := mapper.TokenToDomain(inputTokens)

	if err := ctrl.service.Logout(c.Request.Context(), tokens); err != nil {
		if errors.Is(err, apie.ErrUserNotFound) || errors.Is(err, apie.ErrInvalidToken) ||
			errors.Is(err, apie.ErrNoContent) {
			ctrl.responce(c, http.StatusUnauthorized, gin.H{"massage": "You're login out"})
			return
		}

		ctrl.logger.Error("Service error", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": "server is dead"})
		return
	}

	ctrl.responce(c, http.StatusResetContent, gin.H{"massage": "You're login out"})
}

// Refresh godoc
//
//	@Summary		Refresh access token
//	@Description	This endpoint extends access to the system
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			access_token	header	string	true	"access token"
//	@Param			refresh_token	header	string	true	"refresh token"
//	@Success		200
//	@Failure		401	{object}	dto.Massage
//	@Failure		500	{object}	dto.Massage
//	@Router			/api/refresh [post]
func (ctrl *AuthController) Refresh(c *gin.Context) {
	op := "controller.auth.Refresh"

	accessToken := c.Request.Header.Get("access_token")
	refreshToken := c.Request.Header.Get("refresh_token")

	inputTokens := dto.Token{
		Access:  accessToken,
		Refresh: refreshToken,
	}

	tokens := mapper.TokenToDomain(inputTokens)
	ip := c.ClientIP()
	tokens.Ip = ip

	newTokens, err := ctrl.service.Refresh(c.Request.Context(), tokens)
	if errors.Is(err, apie.ErrInvalidToken) || errors.Is(err, apie.ErrNoContent) || errors.Is(err, apie.ErrNewIp) {
		ctrl.logger.Warn("Unauthorized user trying enter", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusUnauthorized, gin.H{"401": "Unauthorized"})
		return
	}

	if err != nil {
		ctrl.logger.Error("Refresh error", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"error": "server is dead"})
		return
	}

	dto := mapper.TokenToDto(*newTokens)

	c.Writer.Header().Set("access_token", dto.Access)
	c.Writer.Header().Set("refresh_token", dto.Refresh)
	ctrl.responce(c, http.StatusOK, nil)
}

func (ctrl *AuthController) TakeTokens(c *gin.Context) {
	op := "controller.auth.TakeTokens"
	rawId := c.Param("id")
	id := uuid.MustParse(rawId)
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

func (ctrl *AuthController) ValidateToken(c *gin.Context) {
	op := "controllers.auth.ValidateToken"
	token := c.Request.Header.Get("access_token")

	if token == "" {
		ctrl.logger.Warn("Access token is empty", "op", op)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return
	}

	payload, err := ctrl.service.ValidateToken(c.Request.Context(), token)
	if err != nil {
		ctrl.logger.Warn("Validate is not pass", logger.Err(err), "op", op)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.Set("userId", payload.UserID)
	c.Next()
}

func (ctrl *AuthController) ValidateTokenOptional(c *gin.Context) {
	op := "controllers.auth.ValidateToken"
	token := c.Request.Header.Get("access_token")

	if token == "" {
		ctrl.logger.Warn("Access token is empty", "op", op)
		c.Next()
		return
	}

	payload, err := ctrl.service.ValidateToken(c.Request.Context(), token)
	if err != nil {
		ctrl.logger.Warn("Validate is not pass", logger.Err(err), "op", op)
		c.Next()
		return
	}

	c.Set("userId", payload.UserID)
	c.Next()
}
