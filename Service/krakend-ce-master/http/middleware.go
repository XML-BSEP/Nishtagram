package http

import (
	"encoding/json"
	"github.com/devopsfaith/krakend-ce/infrastructure/dto"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
)

func Middleware(ctx *gin.Context) {

	client := resty.New()
	if ctx.FullPath() == "/login" {
		resp, _ := client.R().
			EnableTrace().
			Post("http://127.0.0.1:8081/login")

		var tokenDto dto.TokenDto
		json.Unmarshal(resp.Body(), &tokenDto)
		ctx.SetCookie("jwt", tokenDto.TokenId, 12, "/", "127.0.0.1", true, true)
		ctx.Abort()
		return

	}
	if ctx.FullPath() == "/logout" {
		tokenString := ctx.GetHeader("Cookie")
		//tokenString := authHeader[len(BEARER_SCHEMA)+1:]
		token := dto.TokenDto{TokenId: tokenString}
		tokenByte, _ := json.Marshal(token)
		resp, _ := client.R().
			SetBody(tokenByte).
			EnableTrace().
			Post("http://127.0.0.1:8081/logout")

		var response dto.ServiceResponseDto
		json.Unmarshal(resp.Body(), &response)
		ctx.JSON(resp.StatusCode(), response)
		ctx.Abort()
		return

	}
	if ctx.FullPath() != "/login" && ctx.FullPath() != "/logout"{
		//authHeader := c.GetHeader("Authorization")
		tokenString := ctx.GetHeader("Cookie")
		//tokenString := authHeader[len(BEARER_SCHEMA)+1:]
		token := dto.TokenDto{TokenId: tokenString}
		tokenByte, _ := json.Marshal(token)
		resp, _ := client.R().
			SetBody(tokenByte).
			EnableTrace().
			Post("http://127.0.0.1:8081/validateToken")


		if resp.StatusCode() != 200 {
			ctx.JSON(401, gin.H{"message" : "Unauthorized"})
			ctx.Abort()
		}
	}
}
