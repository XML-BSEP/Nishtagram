package helper

import (
	"encoding/json"
	"github.com/devopsfaith/krakend-ce/infrastructure/dto"
)

func DecodeBody(body []byte) (dto.ServiceResponseDto, error) {
	var response dto.ServiceResponseDto

	err := json.Unmarshal(body, &response)
	return response, err
}
