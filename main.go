package main

import (
	"auth_next/apis"
	_ "auth_next/docs"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// @title           Open Tree Hole Auth
// @version         2.0
// @description     Next Generation of Auth microservice integrated with kong for registration and issuing tokens

// @contact.name   Maintainer Chen Ke
// @contact.url    https://danxi.fduhole.com/about
// @contact.email  dev@fduhole.com

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8000
// @BasePath  /api

func main() {
	app := fiber.New()
	app.Use(recover.New(recover.Config{EnableStackTrace: true}))
	app.Use(logger.New())
	apis.RegisterRoutes(app)

	go func() {
		err := app.Listen("0.0.0.0:8000")
		if err != nil {
			log.Println(err)
		}
	}()

	interrupt := make(chan os.Signal, 1)

	// wait for CTRL-C interrupt
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-interrupt

	// close app
	err := app.Shutdown()
	if err != nil {
		log.Println(err)
	}
}
