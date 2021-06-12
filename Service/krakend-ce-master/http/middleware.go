package http

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/devopsfaith/krakend-ce/infrastructure/mapper"

	"github.com/devopsfaith/krakend-ce/helper"
	"github.com/devopsfaith/krakend-ce/infrastructure/dto"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
)

var annonymous_endpoints = []string{"/register", "/confirmAccount", "/getAll", "/getUserProfileById", "/isAllowedToFollow", "/resendRegistrationCode", "/resetPasswordMail", "/resetPassword", "/validateTotp", "/isTotpEnabled"}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		c.Header("Access-Control-Allow-Origin", "https://localhost:4200")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Header("Access-Control-Allow-Methods", "POST,HEAD,PATCH, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.JSON(204, gin.H{"status": "ok"})
			return
		}
		c.Header("Authorization", "sdasdsadsadsa")

		c.Next()
	}
}

func Middleware(ctx *gin.Context) {
	client := resty.New()

	if ctx.FullPath() == "/login" {

		resp, _ := client.R().
			SetBody(ctx.Request.Body).
			EnableTrace().
			Post("https://127.0.0.1:8091/login")

		if resp.StatusCode() != 200 {
			responseBodyObj, _ := helper.DecodeBody(resp.Body())
			ctx.JSON(resp.StatusCode(), gin.H{"message": responseBodyObj.Message})
			ctx.Abort()
			return
		}
		var authenticatedUserInfoDto dto.AuthenticatedUserInfoDto
		json.Unmarshal(resp.Body(), &authenticatedUserInfoDto)
		//
		//if err != nil {
		//	return
		//}

		ctx.SetCookie("jwt", authenticatedUserInfoDto.Token, 604800000, "/", "127.0.0.1:8080", false, false)
		authenticatedUserInfoFrontDto := mapper.AuthenticatedUserInfoFrontDtoToAuthenticatedUserInfoFrontDto(authenticatedUserInfoDto)

		ctx.JSON(200, authenticatedUserInfoFrontDto)
		ctx.Abort()
		return

	}
	if ctx.FullPath() == "/logout" {
		tokenString := ctx.GetHeader("Cookie")
		//tokenString := authHeader[len(BEARER_SCHEMA)+1:]
		tokenstring1 := strings.Split(tokenString, "=")

		if len(tokenstring1) != 2 {
			ctx.JSON(400, gin.H{"message": "Error parsing cookie"})
			ctx.Abort()
			return
		}
		token := dto.TokenDto{TokenId: tokenstring1[1]}
		tokenByte, _ := json.Marshal(token)
		resp, _ := client.R().
			SetBody(tokenByte).
			EnableTrace().
			Post("https://127.0.0.1:8091/logout")

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

	if ctx.FullPath() == "/validateTotp" {
		tokenString := ctx.GetHeader("Cookie")
		tokenstring1 := strings.Split(tokenString, "jwt=")
		if len(tokenstring1) > 1 {
			token := dto.TokenDto{TokenId: tokenstring1[1]}
			tokenByte, _ := json.Marshal(token)
			resp, _ := client.R().
				SetBody(tokenByte).
				EnableTrace().
				Post("https://127.0.0.1:8091/validateTemporaryToken")
			//token1 := string(resp.Body())
			//ctx.Request.Header.Set("Authorization", token1)
			if resp.StatusCode() != 200 {
				ctx.JSON(401, gin.H{"message": "Unauthorized"})
				ctx.Abort()
				return
			}
			resp2, _ := client.R().
				SetBody(ctx.Request.Body).
				EnableTrace().
				SetHeader("Authorization", string(resp.Body())).
				Post("https://127.0.0.1:8091/validateTotp")

			if resp2.StatusCode() != 200 {
				responseBodyObj, _ := helper.DecodeBody(resp2.Body())
				ctx.JSON(resp2.StatusCode(), gin.H{"message": responseBodyObj.Message})
				ctx.Abort()
				return
			}
			var authenticatedUserInfoDto dto.AuthenticatedUserInfoDto
			json.Unmarshal(resp2.Body(), &authenticatedUserInfoDto)

			ctx.SetCookie("jwt", authenticatedUserInfoDto.Token, 604800000, "/", "127.0.0.1:8080", false, false)
			authenticatedUserInfoFrontDto := mapper.AuthenticatedUserInfoFrontDtoToAuthenticatedUserInfoFrontDto(authenticatedUserInfoDto)

			ctx.JSON(200, authenticatedUserInfoFrontDto)
			ctx.Abort()
			return

		} else {
			token := dto.TokenDto{TokenId: ""}
			tokenByte, _ := json.Marshal(token)
			resp, _ := client.R().
				SetBody(tokenByte).
				EnableTrace().
				Post("https://127.0.0.1:8091/validateTemporaryToken")

			ctx.Request.Header.Set("Authorization", string(resp.Body()))
			if resp.StatusCode() != 200 {
				ctx.JSON(401, gin.H{"message": "Unauthorized"})
				ctx.Abort()
				return
			}
		}
	}
	if !helper.ContainsElement(annonymous_endpoints, ctx.FullPath()) {
		tokenString := ctx.GetHeader("Cookie")
		tokenstring1 := strings.Split(tokenString, "jwt=")
		if len(tokenstring1) > 1 {
			token := dto.TokenDto{TokenId: tokenstring1[1]}
			tokenByte, _ := json.Marshal(token)
			resp, _ := client.R().
				SetBody(tokenByte).
				EnableTrace().
				Post("https://127.0.0.1:8091/validateToken")

			ctx.Request.Header.Set("Authorization", string(resp.Body()))
			if resp.StatusCode() != 200 {
				resp, _ := client.R().
					SetBody(tokenByte).
					EnableTrace().
					Post("https://127.0.0.1:8091/refreshToken")

				if resp.StatusCode() != 200 {
					ctx.JSON(401, gin.H{"message": "Unauthorized"})
					ctx.Abort()
					return
				}
				var refreshTokenDto dto.RefreshTokenDto
				json.Unmarshal(resp.Body(), &refreshTokenDto)
				ctx.Request.Header.Set("Authorization", string(resp.Body()))

				ctx.SetCookie("jwt", refreshTokenDto.TokenUuid, 604800000, "/", "127.0.0.1:8080", false, false)

				ctx.JSON(401, gin.H{"message": "Unauthorized"})
				ctx.Request.Header.Set("Authorization", refreshTokenDto.Token)

			}

		} else {
			token := dto.TokenDto{TokenId: ""}
			tokenByte, _ := json.Marshal(token)
			resp, _ := client.R().
				SetBody(tokenByte).
				EnableTrace().
				Post("https://127.0.0.1:8091/validateToken")
			ctx.Request.Header.Set("Authorization", string(resp.Body()))
			if resp.StatusCode() != 200 {
				ctx.JSON(401, gin.H{"message": "Unauthorized"})
				ctx.Abort()
				return
			}
		}

	}



}
