package dto

type CommonResponseDTO struct {
	Message string `json:"message"`
}

type ErrorResponseDTO struct {
	Kind  string `json:"kind"`
	Code  string `json:"code"`
	Error string `json:"error"`
}
