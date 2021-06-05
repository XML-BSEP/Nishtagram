package mapper

import "github.com/devopsfaith/krakend-ce/infrastructure/dto"

func AuthenticatedUserInfoFrontDtoToAuthenticatedUserInfoFrontDto(inf dto.AuthenticatedUserInfoDto) dto.AuthenticatedUserInfoFrontDto {
	return dto.AuthenticatedUserInfoFrontDto{
		Id: inf.Id,
		Role: inf.Role,
	}
}
