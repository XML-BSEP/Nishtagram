package http

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/devopsfaith/krakend-ce/grpc/client"
	"github.com/devopsfaith/krakend-ce/helper/http_helper"
	"google.golang.org/grpc/metadata"

	"github.com/devopsfaith/krakend-ce/infrastructure/mapper"

	pb "github.com/devopsfaith/krakend-ce/grpc/authentication_service/service"
	"github.com/devopsfaith/krakend-ce/helper"
	"github.com/devopsfaith/krakend-ce/infrastructure/dto"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
)

var annonymous_endpoints = []string{"/register", "/confirmAccount", "/getAll", "/getUserProfileById", "/isAllowedToFollow", "/resendRegistrationCode", "/resetPasswordMail",
	"/resetPassword", "/validateTotp", "/isTotpEnabled", "/getPostLocationsByLocationContaining", "/post/getPostByIdForSearch", "/searchUser", "/getPostsByTag",
	"/agent", "/agent/validate", "/room/:roomId", "/ws/:roomId", "/message/:receiver/:sender", "/createAd",
	"/getAdsByAgent", "/deleteDisposableCampaign", "/getAllDisposableCampaigns", "/getAllMultipleCampaigns", "/generateStatisticReport", "/updateMultipleCampaign",
 	"/deleteMultipleCampaign", "/createDisposableCampaign", "/createMultipleCampaign"}

const cookie_maxAge = 604800000

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if os.Getenv("DOCKER_ENV") == "" {
			c.Header("Access-Control-Allow-Origin", "https://localhost:4200")
		} else {
			c.Header("Access-Control-Allow-Origin", "http://localhost:4200")
		}
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

//TODO:Remove this function after testing grpc

func Middleware(ctx *gin.Context) {
	client := resty.New()

	/*if ctx.FullPath() == "/login" {

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

	}*/
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
	/*if !helper.ContainsElement(annonymous_endpoints, ctx.FullPath()) {
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

	}*/

}

func GrpcMiddleware(ctx *gin.Context) {

	var domain string
	if os.Getenv("DOCKER_ENV") == "" {
		domain = "127.0.0.1"
	} else {
		domain = "authms"
	}
	grpcClient, err := client.NewauthenticationClient(domain + ":8079")

	if err != nil {
		ctx.JSON(500, gin.H{"message": err})
		ctx.Abort()
		return
	}

	if ctx.FullPath() == "/login" {
		Login(ctx, grpcClient)
		return
	}

	if ctx.FullPath() == "/logout" {
		Logout(ctx, grpcClient)
		return
	}
	if ctx.FullPath() == "/validateTotp" {
		ValidateTotp(ctx, grpcClient)
		return
	}

	if !helper.ContainsElement(annonymous_endpoints, ctx.FullPath()) {
		token, isValid := IsTokenValid(ctx, grpcClient)
		if !isValid {
			ctx.Abort()
			return
		}

		ctx.Request.Header.Set("Authorization", *token)
	}
}

func Login(ctx *gin.Context, client pb.AuthenticationClient) {

	decoder := json.NewDecoder(ctx.Request.Body)
	var authenticationCredentials dto.AuthenticationDto
	err := decoder.Decode(&authenticationCredentials)
	if err != nil {
		ctx.JSON(500, "Can not decode login credentials")
		ctx.Abort()
		return
	}

	loginCredentials := &pb.LoginCredentials{Username: authenticationCredentials.Username, Password: authenticationCredentials.Password}
	response, err := client.Login(ctx, loginCredentials)

	if err != nil {
		ctx.JSON(400, gin.H{"message": "Invalid credentials"})
		ctx.Abort()
		return
	}

	http_helper.SetCookies(ctx, "at", response.AccessToken, cookie_maxAge)
	http_helper.SetCookies(ctx, "rt", response.RefreshToken, cookie_maxAge)

	userInfo := dto.AuthenticatedUserInfoFrontDto{Id: response.Id, Role: response.Role}
	ctx.JSON(200, userInfo)
	ctx.Abort()
	return
}

func Logout(ctx *gin.Context, client pb.AuthenticationClient) {

	tokens := http_helper.GetTokens(ctx)
	accessTokenId := tokens["at"]
	refreshTokenId := tokens["rt"]
	authRequest := &pb.Tokens{Token: accessTokenId, RefreshToken: refreshTokenId}
	_, err := client.Logout(ctx, authRequest)

	if err != nil {
		ctx.JSON(400, gin.H{"message": "Logout error"})
		ctx.Abort()
		return
	}

	ctx.JSON(200, gin.H{"message": "Logout successful"})
	ctx.Abort()
	return
}

func IsTokenValid(ctx *gin.Context, client pb.AuthenticationClient) (*string, bool) {

	tokens := http_helper.GetTokens(ctx)
	accessTokenId := tokens["at"]
	refreshTokenId := tokens["rt"]

	validationRequest := &pb.Tokens{Token: accessTokenId, RefreshToken: refreshTokenId}

	response, err := client.ValidateToken(ctx, validationRequest)

	if err != nil {
		ctx.JSON(400, gin.H{"message": "Your token is not valid"})
		return nil, false
	}

	if response.AccessTokenUuid != accessTokenId {
		http_helper.SetCookies(ctx, "at", response.AccessTokenUuid, cookie_maxAge)
	}

	http_helper.SetCookies(ctx, "rt", response.RefreshTokenUuid, cookie_maxAge)

	return &response.AccessToken, true
}

func ValidateTotp(ctx *gin.Context, client pb.AuthenticationClient) {
	tokens := http_helper.GetTokens(ctx)
	accessTokenId := tokens["at"]

	decoder := json.NewDecoder(ctx.Request.Body)
	var totpValidationDto dto.TotpValidationDto

	err := decoder.Decode(&totpValidationDto)

	if err != nil {
		ctx.JSON(500, "Can not read passcode")
		ctx.Abort()
		return
	}

	grpcCtx := setGrpcAuthHeader(ctx, accessTokenId)
	at := &pb.AccessToken{AccessToken: accessTokenId}
	in := &pb.TotpValidation{Passcode: totpValidationDto.Passcode, AccessToken: at}
	resp, err := client.ValidateTotp(grpcCtx, in)

	if err != nil {
		ctx.JSON(400, "Your passcode is not valid")
		ctx.Abort()
		return
	}

	http_helper.SetCookies(ctx, "at", resp.AccessToken, cookie_maxAge)
	http_helper.SetCookies(ctx, "rt", resp.RefreshToken, cookie_maxAge)
	ret := dto.AuthenticatedUserInfoFrontDto{Id: resp.Id, Role: resp.Role}
	ctx.JSON(200, ret)
	ctx.Abort()
	return
}

func setGrpcAuthHeader(ctx *gin.Context, token string) context.Context {

	headers := map[string][]string{}
	headers2 := []string{token}

	headers["authorization"] = headers2

	grpcCtx := metadata.NewOutgoingContext(ctx, headers)

	return grpcCtx
}
