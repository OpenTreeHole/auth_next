//	@title			Open Tree Hole Auth
//	@version		2.0
//	@description	Next Generation of Auth microservice integrated with kong for registration and issuing tokens

//	@contact.name	Maintainer Chen Ke
//	@contact.url	https://danxi.fduhole.com/about
//	@contact.email	dev@danta.tech

//	@license.name	Apache 2.0
//	@license.url	https://www.apache.org/licenses/LICENSE-2.0.html

//	@host		localhost:8000
//	@BasePath	/api

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/opentreehole/go-common"
	"github.com/robfig/cron/v3"
	"github.com/rs/zerolog/log"

	"auth_next/apis"
	"auth_next/config"
	_ "auth_next/docs"
	"auth_next/models"
	"auth_next/utils/auth"
	"auth_next/utils/kong"
)

func init() {
	// set default time zone
	loc, _ := time.LoadLocation("Asia/Shanghai")
	time.Local = loc
}

func main() {
	config.InitConfig()
	auth.InitVerificationCodeCache()
	models.InitDB()
	apis.Init()

	// connect to kong
	if !config.Config.Standalone {
		err := kong.Ping()
		if err != nil {
			log.Fatal().Err(err).Msg("kong ping failed")
		}
	}

	app := fiber.New(fiber.Config{
		ErrorHandler:          common.ErrorHandler,
		JSONEncoder:           json.Marshal,
		JSONDecoder:           json.Unmarshal,
		DisableStartupMessage: true,
		BodyLimit:             128 * 1024 * 1024,
	})
	RegisterMiddlewares(app)
	apis.RegisterRoutes(app)

	cancel := startTasks()

	go func() {
		err := app.Listen("0.0.0.0:8000")
		if err != nil {
			log.Fatal().Err(err).Msg("app listen failed")
		}
	}()

	interrupt := make(chan os.Signal, 1)

	// wait for CTRL-C interrupt
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-interrupt

	// close app
	err := app.Shutdown()
	if err != nil {
		log.Err(err).Msg("error shutdown app")
	}

	// stop tasks
	cancel()
}

func startTasks() context.CancelFunc {
	_, cancel := context.WithCancel(context.Background())

	c := cron.New()
	_, err := c.AddFunc("CRON_TZ=Asia/Shanghai 0 0 * * *", models.ActiveStatusTask) // run every day 00:00 +8:00
	if err != nil {
		log.Fatal().Err(err).Msg("cron add func failed")
	}
	go c.Start()
	return cancel
}

func RegisterMiddlewares(app *fiber.App) {
	app.Use(recover.New(recover.Config{
		EnableStackTrace:  true,
		StackTraceHandler: common.StackTraceHandler,
	}))
	app.Use(common.MiddlewareGetUserID)
	if config.Config.Mode != "bench" {
		app.Use(common.MiddlewareCustomLogger)
	}
	if config.Config.Mode == "dev" {
		app.Use(cors.New(cors.Config{AllowOrigins: "*"})) // for swag docs
	}
}
