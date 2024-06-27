package dto

type ConfigDTO struct {
	AccessTokenTTLsec  int `json:"accessTokenTTLsec"`
	RefreshTokenTTLsec int `json:"refreshTokenTTLsec"`
}
