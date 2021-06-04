package http

import (
	"encoding/json"
	"fmt"
	"github.com/devopsfaith/krakend-ce/infrastructure/dto"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"strings"
)
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		c.Header("Access-Control-Allow-Origin", "https://localhost:4200")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST,HEAD,PATCH, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.JSON(204, gin.H{"status":"ok"})
			return
		}

		c.Next()
	}
}

func Middleware(ctx *gin.Context) {
	client := resty.New()

	if ctx.FullPath() == "/login" {
		resp, _ := client.R().
			EnableTrace().
			Post("http://127.0.0.1:8091/login")

		var tokenDto dto.TokenDto
		json.Unmarshal(resp.Body(), &tokenDto)
		//
		//if err != nil {
		//	return
		//}
		fmt.Print(tokenDto)

		ctx.SetCookie("jwt", tokenDto.TokenId, 1000000000000 , "/", "127.0.0.1", false, false)
		ctx.Abort()
		return

	}
	if ctx.FullPath() == "/logout" {
		tokenString := ctx.GetHeader("Cookie")
		//tokenString := authHeader[len(BEARER_SCHEMA)+1:]
		tokenstring1 := strings.Split(tokenString,"=")

		token := dto.TokenDto{TokenId: tokenstring1[1]}
		tokenByte, _ := json.Marshal(token)
		resp, _ := client.R().
			SetBody(tokenByte).
			EnableTrace().
			Post("http://127.0.0.1:8091/logout")

		var response dto.ServiceResponseDto
		err := json.Unmarshal(resp.Body(), &response)
		if err != nil {
			return
		}
		fmt.Print(string(tokenByte))

		ctx.JSON(resp.StatusCode(), response)
		ctx.Abort()
		return

	}
	if ctx.FullPath() != "/login" && ctx.FullPath() != "/logout"{
		//authHeader := c.GetHeader("Authorization")
		tokenString := ctx.GetHeader("Cookie")
		tokenstring1 := strings.Split(tokenString,"=")
		//tokenString := authHeader[len(BEARER_SCHEMA)+1:]
		ctx.Request.Header.Set("Authorization", "dsfdsfsd")
		token := dto.TokenDto{TokenId: tokenstring1[1]}
		tokenByte, _ := json.Marshal(token)
		resp, _ := client.R().
			SetBody(tokenByte).
			EnableTrace().
			Post("http://127.0.0.1:8091/validateToken")
		fmt.Println(resp.Body())
		ctx.Header("Authorization", string(resp.Body()))
		ctx.Request.Header.Set("Authorization", string(resp.Body()))/*
		if resp.StatusCode() != 200 {
			ctx.JSON(401, gin.H{"message" : "Unauthorized"})
			ctx.Abort()
		}*/
	}
}
