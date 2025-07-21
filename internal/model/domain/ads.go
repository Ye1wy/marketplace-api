package domain

import (
	"time"

	"github.com/google/uuid"
)

type Ads struct {
	Id          uuid.UUID
	Title       string
	Description string
	Price       float64
	ImageURL    string
	AuthorId    uuid.UUID
	AuthorName  string
	CreatedAt   time.Time
	IsMine      bool
}

type Filters struct {
	Page     int
	PageSize int
	SortBy   string
	Order    string
	MinPrice float64
	MaxPrice float64
	Offset   int
	AuthorId uuid.UUID
}
