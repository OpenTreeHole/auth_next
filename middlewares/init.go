package middlewares

import (
	"auth_next/config"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/opentreehole/go-common"
)

func RegisterMiddlewares(app *fiber.App) {
	app.Use(recover.New(recover.Config{EnableStackTrace: true}))
	app.Use(common.MiddlewareGetUserID)
	if config.Config.Mode != "bench" {
		app.Use(common.MiddlewareCustomLogger)
	}
	if config.Config.Mode == "dev" {
		app.Use(cors.New(cors.Config{AllowOrigins: "*"})) // for swag docs
	}
}
