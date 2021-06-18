package http_helper

import "github.com/gin-gonic/gin"

func GetTokens(ctx *gin.Context) map[string]string {
	cookies := ctx.Request.Cookies()

	cookiesMap := make(map[string]string)
	for _, val := range cookies {
		cookiesMap[val.Name] = val.Value
	}

	return cookiesMap
}

func SetCookies(ctx *gin.Context, name, value string, maxAge int) {


	if value != "" && name != ""{
		ctx.SetCookie(name, value, maxAge, "/", "127.0.0.1:8080", false, false)
	}

}
