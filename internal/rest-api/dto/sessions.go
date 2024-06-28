package dto

import (
	"go-jwt-auth/internal/rest-api/entities"
	"time"
)

type SessionDTO struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"userAgent"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type SessionsDTO struct {
	Sessions []SessionDTO `json:"sessions"`
}

func SessionsDTOFromEntities(sessions []*entities.RefreshToken) *SessionsDTO {
	dto := &SessionsDTO{
		Sessions: make([]SessionDTO, 0),
	}

	for _, session := range sessions {
		dto.Sessions = append(dto.Sessions, SessionDTO{
			IP:        session.GetIP(),
			UserAgent: session.GetUserAgent(),
			CreatedAt: session.GetCreatedAt(),
			UpdatedAt: session.GetUpdatedAt(),
		})
	}

	return dto
}
