package service

import (
	apie "auth-service/internal/errors"
	mailer "auth-service/internal/mail"
	"auth-service/internal/model/domain"
	"auth-service/pkg/logger"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TokenWrite interface {
	PinRefreshToken(ctx context.Context, token domain.RefreshToken) error
	Delete(ctx context.Context, token domain.RefreshToken) error
}

type TokenRead interface {
	GetById(ctx context.Context, id uuid.UUID) (*domain.RefreshToken, error)
	GetByUsername(ctx context.Context, username string) ([]domain.RefreshToken, error)
}

type UserRead interface {
	GetByUsername(ctx context.Context, username string) (*domain.User, error)
	GetById(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

type UserWrite interface {
	Create(ctx context.Context, user domain.User) error
}

type authService struct {
	tokenWriter TokenWrite
	tokenReader TokenRead
	userWriter  UserWrite
	userReader  UserRead
	diller      mailer.Mailer
	logger      *logger.Logger
	secretKey   string
}

func NewAuthService(tokenW TokenWrite, tokenR TokenRead, userR UserRead, userW UserWrite, mailer mailer.Mailer, logger *logger.Logger, secretKey string) *authService {
	return &authService{
		tokenWriter: tokenW,
		tokenReader: tokenR,
		userWriter:  userW,
		userReader:  userR,
		diller:      mailer,
		logger:      logger,
		secretKey:   secretKey,
	}
}

func (s *authService) SignUp(ctx context.Context, user domain.User) error {
	op := "service.authService.SignUp"

	if user.Username == "" || user.Password == "" || user.Email == "" {
		s.logger.Debug("domain user is empty", "op", op)
		return fmt.Errorf("%s: %w", op, apie.ErrNoContent)
	}

	cryptPassword, err := hashPassword(user.Password)
	if err != nil {
		return fmt.Errorf("%s: %v", op, err)
	}

	user.Password = cryptPassword

	if err := s.userWriter.Create(ctx, user); err != nil {
		s.logger.Debug("Creating error", logger.Err(err), "op", op)
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *authService) Login(ctx context.Context, user domain.User) (*domain.Token, error) {
	op := "service.authService.Login"

	check, err := s.userReader.GetByUsername(ctx, user.Username)
	if err != nil {
		s.logger.Error("Failed get username", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	s.logger.Debug("data from user repo", "userId", check.Username, "password", check.Password, "op", op)

	if user.Username != check.Username {
		s.logger.Warn("Username is incorrct", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrIncorrectUsernameOrPassword)
	}

	err = bcrypt.CompareHashAndPassword([]byte(check.Password), []byte(user.Password))
	if err != nil {
		s.logger.Error("Compare hash is failed", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrIncorrectUsernameOrPassword)
	}

	sessionId := uuid.New()
	accessPayload := domain.AccessTokenPayload{
		UserID:    check.Id,
		Ip:        user.Ip,
		SessionId: sessionId,
	}

	access, err := genereateAccessToken(accessPayload, s.secretKey)
	if err != nil {
		s.logger.Warn("Access token not signed", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %v", op, err)
	}

	refreshPayload := domain.RefreshTokenPayload{
		UserId:    check.Id,
		SessionId: sessionId,
	}

	refresh, err := generateRefreshToken(refreshPayload)
	if err != nil {
		s.logger.Warn("Error on generate refresh token", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %v", op, err)
	}

	tokens := domain.Token{
		Access:  access,
		Refresh: refresh.Refresh,
	}

	s.logger.Debug("params", "check user", check.Username, "userId", user.Username, "a", access, "r", refresh)
	s.logger.Debug("param session", "id", sessionId)
	if err := s.tokenWriter.PinRefreshToken(ctx, *refresh); err != nil {
		s.logger.Error("Pin refresh token problem", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &tokens, nil
}

func (s *authService) Logout(ctx context.Context, token domain.Token) error {
	op := "service.authService.Logout"
	jwtMap, ok := getFromToken(token.Access, s.secretKey)
	if !ok {
		s.logger.Warn("Invalid token", "op", op)
		return fmt.Errorf("%s: %w", op, apie.ErrInvalidToken)
	}

	rawUserId, ok := jwtMap["userId"].(string)
	if !ok {
		s.logger.Error("Username not contained in jwt map", "op", op)
		return fmt.Errorf("%s: %w", op, apie.ErrConversationProblem)
	}

	userId, err := uuid.Parse(rawUserId)
	if err != nil {
		s.logger.Error("Parse string uuid is failed", logger.Err(err), "op", op)
		return fmt.Errorf("%s: %v", op, err)
	}

	check, err := s.userReader.GetById(ctx, userId)
	if err != nil {
		s.logger.Error("Failed get user by id", logger.Err(err), "op", op)
		return fmt.Errorf("%s: %w", op, err)
	}

	dbToken, err := s.tokenReader.GetByUsername(ctx, check.Username)
	if err != nil {
		s.logger.Error("Failed to get refresh token from database", logger.Err(err), "op", op)
		return fmt.Errorf("%s: %w", op, err)
	}

	var target domain.RefreshToken
	found := false

	for _, item := range dbToken {
		err := bcrypt.CompareHashAndPassword([]byte(item.Hash), []byte(token.Refresh))
		if err == nil {
			found = true
			target = item
		}
	}

	if !found {
		s.logger.Warn("hash not found", "op", op)
		return fmt.Errorf("%s: %w", op, apie.ErrNoContent)
	}

	if err := s.tokenWriter.Delete(ctx, target); err != nil {
		s.logger.Error("Failed delete refresh token from database", logger.Err(err), "op", op)
		return fmt.Errorf("%s: %v", op, err)
	}

	return nil
}

func (s *authService) Refresh(ctx context.Context, token domain.Token) (*domain.Token, error) {
	op := "service.authService.Refresh"
	jwtMap, ok := getFromToken(token.Access, s.secretKey)
	if !ok {
		s.logger.Error("Failed to get target username from JWT token payload", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrInvalidToken)
	}

	rawUserId, ok := jwtMap["userId"].(string)
	if !ok {
		s.logger.Error("Username not contained in jwt map", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrConversationProblem)
	}

	userId, err := uuid.Parse(rawUserId)
	if err != nil {
		s.logger.Error("Parse string uuid is failed", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %v", op, err)
	}

	check, err := s.userReader.GetById(ctx, userId)
	if err != nil {
		s.logger.Error("Failed get user by id", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	s.logger.Debug("Check username", "userId", userId, "op", op)

	dbToken, err := s.tokenReader.GetByUsername(ctx, check.Username)
	if err != nil {
		s.logger.Error("Failed to get refresh token from database", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %v", op, err)
	}

	var target domain.RefreshToken
	found := false

	for _, item := range dbToken {
		err := bcrypt.CompareHashAndPassword([]byte(item.Hash), []byte(token.Refresh))
		if err == nil {
			found = true
			target = item
		}
	}

	if !found {
		s.logger.Warn("hash not found", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrNoContent)
	}

	diff := time.Now().Compare(target.ExpiresAt)
	if diff > 0 {
		s.logger.Debug("Refresh token is expired", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrRefreshIsExpired)
	}

	ip, ok := jwtMap["ip"].(string)
	if !ok {
		s.logger.Error("Conversation problem: ip is not contains in jwt map", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrConversationProblem)
	}

	s.logger.Debug("Check ip", "ip", ip, "op", op)

	if ip != token.Ip {
		user, err := s.userReader.GetById(ctx, target.UserId)
		if err != nil {
			s.logger.Debug("Not found or something wrong", logger.Err(err), "op", op)
			return nil, fmt.Errorf("%s: %w", op, err)
		}

		s.logger.Debug("Ip not same", "op", op)
		if err := s.tokenWriter.Delete(ctx, target); err != nil {
			s.logger.Error("delete wronge", logger.Err(err), "op", op)
			return nil, fmt.Errorf("%s: %w", op, err)
		}

		if err := s.diller.SendMail(user.Email, "Warning", "Your ip is change"); err != nil {
			s.logger.Error("send wrong", logger.Err(err), "op", op)
			return nil, fmt.Errorf("%s: %w", op, err)
		}

		return nil, fmt.Errorf("%s: %w", op, apie.ErrNewIp)
	}

	rawSessionId, ok := jwtMap["sessionId"].(string)
	if !ok {
		s.logger.Error("Session id is not contained in jwt map", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrConversationProblem)
	}

	oldSessionId, err := uuid.Parse(rawSessionId)
	if err != nil {
		s.logger.Error("Failed to parse session uuid from string", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %v", op, err)
	}

	refreshTokenData, err := s.tokenReader.GetById(ctx, oldSessionId)
	if err != nil {
		s.logger.Error("Get session data is failed", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if oldSessionId != refreshTokenData.SessionId {
		s.logger.Warn("Taked token is invalid", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrInvalidToken)
	}

	newSessionId := uuid.New()

	accessPayload := domain.AccessTokenPayload{
		UserID:    userId,
		Ip:        token.Ip,
		SessionId: newSessionId,
	}

	access, err := genereateAccessToken(accessPayload, s.secretKey)
	if err != nil {
		s.logger.Error("Access generation problem", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %v", op, err)
	}

	refreshPayload := domain.RefreshTokenPayload{
		UserId:    target.UserId,
		SessionId: newSessionId,
	}

	newRefresh, err := generateRefreshToken(refreshPayload)
	if err != nil {
		s.logger.Error("Refresh generation problem", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %v", op, err)
	}

	res := domain.Token{
		Ip:      token.Ip,
		Access:  access,
		Refresh: newRefresh.Refresh,
	}

	if err := s.tokenWriter.Delete(ctx, target); err != nil {
		s.logger.Error("Failed to delete old refresh token", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if err := s.tokenWriter.PinRefreshToken(ctx, *newRefresh); err != nil {
		s.logger.Error("Failed to pin new refresh token", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &res, nil
}

func (s *authService) Secret(ctx context.Context, id uuid.UUID, ip string) (*domain.Token, error) {
	op := "service.authService.Secret"
	user, err := s.userReader.GetById(ctx, id)
	if err != nil {
		s.logger.Warn("Can't get user by id", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	sessionId := uuid.New()
	accessPayload := domain.AccessTokenPayload{
		UserID:    user.Id,
		Ip:        ip,
		SessionId: sessionId,
	}

	access, err := genereateAccessToken(accessPayload, s.secretKey)
	if err != nil {
		s.logger.Error("access token not signed", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	refreshPayload := domain.RefreshTokenPayload{
		UserId:    user.Id,
		SessionId: sessionId,
	}

	refresh, err := generateRefreshToken(refreshPayload)
	if err != nil {
		s.logger.Error("Error on generate refresh token", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	tokens := domain.Token{
		Access:  access,
		Refresh: refresh.Refresh,
	}

	s.logger.Debug("params", "userId", user.Username, "a", access, "r", refresh)

	if err := s.tokenWriter.PinRefreshToken(ctx, *refresh); err != nil {
		s.logger.Debug("Repository error", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &tokens, nil
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func genereateAccessToken(payload domain.AccessTokenPayload, secret string) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sessionId": payload.SessionId,
		"userId":    payload.UserID,
		"ip":        payload.Ip,
		"exp":       time.Now().Add(time.Minute * 15).Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return accessTokenString, nil
}

func generateRefreshToken(payload domain.RefreshTokenPayload) (*domain.RefreshToken, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}

	refresh := base64.URLEncoding.EncodeToString(token)

	hash, err := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	res := domain.RefreshToken{
		SessionId: payload.SessionId,
		UserId:    payload.UserId,
		Refresh:   refresh,
		Hash:      string(hash),
		ExpiresAt: time.Now().Add(time.Hour * 7),
		CreatedAt: time.Now(),
	}

	return &res, nil
}

func getFromToken(tokenStr, secret string) (jwt.MapClaims, bool) {
	key := []byte(secret)
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, http.ErrAbortHandler
		}
		return key, nil
	})

	if err != nil {
		return nil, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	}

	return nil, false
}

// Middewarre for a preliminary check
func (s *authService) ValidateToken(ctx context.Context, accessToken string) (*domain.AccessTokenPayload, error) {
	op := "service.authService.ValidateToken"
	jwtMap, ok := getFromToken(accessToken, s.secretKey)
	if !ok {
		s.logger.Error("Failed get jwt map", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrInvalidToken)
	}

	rawUserId, ok := jwtMap["userId"].(string)
	if !ok {
		s.logger.Error("Conversation problem: username is not contained", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrInvalidToken)
	}

	userId, err := uuid.Parse(rawUserId)
	if err != nil {
		s.logger.Error("Parse user id is failed", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %v", op, err)
	}

	user, err := s.userReader.GetById(ctx, userId)
	if err != nil {
		s.logger.Error("UserId is not found", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrInvalidToken)
	}

	expFloat, ok := jwtMap["exp"].(float64)
	if !ok {
		s.logger.Error("Conversation problem: expier time is not contained", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrConversationProblem)
	}

	exp := time.Unix(int64(expFloat), 0)

	diff := time.Now().Compare(exp)

	if diff >= 0 {
		s.logger.Warn("Access token is expired", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrAccessIsExpired)
	}

	rawSessionId, ok := jwtMap["sessionId"].(string)
	if !ok {
		s.logger.Error("Conversation problem: session id is not contained", "op", op)
		return nil, fmt.Errorf("%s: %w", op, apie.ErrInvalidToken)
	}

	sessionId, err := uuid.Parse(rawSessionId)
	if err != nil {
		s.logger.Error("Failed parse string with uuid", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s: %v", op, err)
	}

	_, err = s.tokenReader.GetById(ctx, sessionId)
	if err != nil {
		if errors.Is(err, apie.ErrSessionNotFound) {
			s.logger.Error("Session id is not contained in jwt map", "op", op)
			return nil, fmt.Errorf("%s: %w", op, apie.ErrInvalidToken)
		}

		s.logger.Error("Failed to get session by id", logger.Err(err), "op", op)
		return nil, fmt.Errorf("%s, %v", op, err)
	}

	payload := domain.AccessTokenPayload{
		UserID:    user.Id,
		SessionId: sessionId,
	}

	return &payload, nil
}
