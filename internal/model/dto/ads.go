package dto

import "time"

type AdsRequest struct {
	Title        string  `json:"title" binding:"required"`
	Descripstion string  `json:"descripstion" binding:"required"`
	Price        float64 `json:"price" binding:"required"`
	ImageURL     string  `json:"image_url" binding:"required"`
}

type AdsResponse struct {
	Title        string    `json:"title"`
	Descripstion string    `json:"descripstion"`
	Price        float64   `json:"price"`
	ImageURL     string    `json:"image_url"`
	AuthorName   string    `json:"author_name"`
	CreatedAt    time.Time `json:"created_at"`
	IsMine       bool      `json:"is_mine"`
}
