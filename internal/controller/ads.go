package controller

import (
	"auth-service/internal/mapper"
	"auth-service/internal/model/domain"
	"auth-service/internal/model/dto"
	"auth-service/pkg/logger"
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AdsService interface {
	Create(ctx context.Context, ads domain.Ads) error
	GetAll(ctx context.Context, filters domain.Filters) ([]domain.Ads, error)
}

type AdsController struct {
	*BaseController
	service AdsService
}

func NewAds(service AdsService, logger *logger.Logger) *AdsController {
	baseController := NewBaseController(logger)
	return &AdsController{
		BaseController: baseController,
		service:        service,
	}
}

func (ctrl *AdsController) Create(c *gin.Context) {
	op := "controller.ads.Create"

	var input dto.AdsRequest

	if err := c.ShouldBind(&input); err != nil {
		ctrl.logger.Warn("Taked invalid input", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"massage": "Invalid payload"})
		return
	}

	ads := mapper.AdsToDomain(input)

	rawId, ok := c.Get("userId")
	if !ok {
		ctrl.logger.Error("Cannot get user id from context", "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"massage": "server is dead"})
		return
	}

	userId, ok := rawId.(uuid.UUID)
	if !ok {
		ctrl.logger.Error("User UUID conversation failed", "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"massage": "server is dead"})
		return
	}

	ads.AuthorId = userId

	if err := ctrl.service.Create(c.Request.Context(), ads); err != nil {
		ctrl.logger.Error("Failed to create ads", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"massage": "Server is dead"})
		return
	}

	ctrl.responce(c, http.StatusCreated, input)
}

func (ctrl *AdsController) GetAll(c *gin.Context) {
	op := "controller.ads.GetAll"
	var filter domain.Filters

	rawId, ok := c.Get("userId")
	if ok {
		userId, ok := rawId.(uuid.UUID)
		if !ok {
			ctrl.logger.Error("User UUID conversation failed", "op", op)
			ctrl.responce(c, http.StatusInternalServerError, gin.H{"massage": "server is dead"})
			return
		}

		filter.AuthorId = userId
	}

	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil {
		ctrl.logger.Warn("Page number is invalid", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"massage": "Incorrect page number"})
		return
	}

	pageSize, err := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	if err != nil {
		ctrl.logger.Warn("Page size number is invalid", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"massage": "Incorrect page size number"})
		return
	}
	sortBy := c.DefaultQuery("sort", "date") // "price" or "date"
	order := c.DefaultQuery("order", "desc") // "asc" or "desc"
	minPrice, err := strconv.Atoi(c.DefaultQuery("minPrice", "0"))
	if err != nil {
		ctrl.logger.Warn("Min price number is invalid", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"massage": "Incorrect min price number"})
		return
	}

	maxPrice, err := strconv.Atoi(c.DefaultQuery("maxPrice", "1000000000"))
	if err != nil {
		ctrl.logger.Warn("Min price number is invalid", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusBadRequest, gin.H{"massage": "Incorrect min price number"})
		return
	}

	filter.Page = page
	filter.PageSize = pageSize
	filter.SortBy = sortBy
	filter.Order = order
	filter.MinPrice = float64(minPrice)
	filter.MaxPrice = float64(maxPrice)
	filter.Offset = (page - 1) * pageSize

	ads, err := ctrl.service.GetAll(c.Request.Context(), filter)
	if err != nil {
		ctrl.logger.Error("Failed get all", logger.Err(err), "op", op)
		ctrl.responce(c, http.StatusInternalServerError, gin.H{"massage": "server is dead"})
		return
	}

	var output []dto.AdsResponse

	for _, ad := range ads {
		output = append(output, mapper.AdsToResponse(ad))
	}

	ctrl.responce(c, http.StatusOK, output)
}
