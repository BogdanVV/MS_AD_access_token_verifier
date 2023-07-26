package main

import (
	"github.com/gin-gonic/gin"
	"github.com/subosito/gotenv"

	"test_auth/handlers"
	"test_auth/middleware"
)

func main() {
	gotenv.Load()

	app := gin.Default()

	app.Use(middleware.CORSMiddleware)

	app.GET("/test", handlers.MainHandler)

	app.Run(":8888")
}
