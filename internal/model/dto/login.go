package dto

type LoginRequest struct {
	Username string `json:"username" xml:"username" binding:"required"`
	Password string `json:"password" xml:"password" binding:"required"`
}

type LoginResponce struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
