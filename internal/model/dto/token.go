package dto

type Token struct {
	Access  string `json:"access" xml:"access" binding:"required"`
	Refresh string `json:"refresh" xml:"refresh" binding:"required"`
}
