package dto

type TotpValidationDto struct {
	UserId string `json:"user_id"`
	Passcode string `json:"passcode"`
}
