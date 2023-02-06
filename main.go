//	@title			Open Tree Hole Auth
//	@version		2.0
//	@description	Next Generation of Auth microservice integrated with kong for registration and issuing tokens

//	@contact.name	Maintainer Chen Ke
//	@contact.url	https://danxi.fduhole.com/about
//	@contact.email	dev@fduhole.com

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

//	@host		localhost:8000
//	@BasePath	/api

package main

import (
	"auth_next/apis"
	"auth_next/config"
	_ "auth_next/docs"
	"auth_next/middlewares"
	"auth_next/models"
	"auth_next/utils"
	"auth_next/utils/kong"
	"context"
	"encoding/json"
	"github.com/gofiber/fiber/v2"
	"github.com/robfig/cron/v3"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	config.InitConfig()
	models.InitDB()
	apis.InitShamirStatus()

	// connect to kong
	err := kong.Ping()
	if err != nil {
		panic(err)
	}

	app := fiber.New(fiber.Config{
		ErrorHandler: utils.MyErrorHandler,
		JSONEncoder:  json.Marshal,
		JSONDecoder:  json.Unmarshal,
	})
	middlewares.RegisterMiddlewares(app)
	apis.RegisterRoutes(app)

	cancel := startTasks()

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
	err = app.Shutdown()
	if err != nil {
		log.Println(err)
	}

	// stop tasks
	cancel()
}

func startTasks() context.CancelFunc {
	_, cancel := context.WithCancel(context.Background())
	go models.RefreshAdminList()

	c := cron.New()
	_, err := c.AddFunc("CRON_TZ=Asia/Shanghai 0 0 * * *", models.ActiveStatusTask) // run every day 00:00 +8:00
	if err != nil {
		panic(err)
	}
	go c.Start()
	return cancel
}
