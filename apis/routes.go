package apis

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"

	"auth_next/config"
)

func RegisterRoutes(app *fiber.App) {
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Redirect("/api")
	})
	// docs
	app.Get("/docs", func(c *fiber.Ctx) error {
		return c.Redirect("/docs/index.html")
	})
	app.Get("/docs/*", swagger.HandlerDefault)

	// meta
	routes := app.Group("/api")
	routes.Get("/", Index)

	// token
	routes.Post("/login", Login)
	routes.Get("/logout", Logout)
	routes.Post("/refresh", Refresh)

	// account management
	routes.Get("/verify/email", VerifyWithEmail)
	routes.Get("/verify/email/:email", VerifyWithEmailOld)
	routes.Get("/verify/apikey", VerifyWithApikey)
	routes.Post("/register", Register)
	routes.Put("/register", ChangePassword)
	routes.Patch("/register/_webvpn", ChangePassword)
	routes.Delete("/users/me", DeleteUser)
	routes.Delete("/users/:id", DeleteUserByID)

	// register questions
	if config.Config.EnableRegisterQuestions {
		routes.Get("/register/questions", RetrieveQuestions)
		routes.Post("/register/questions/_answer", AnswerQuestions)
		routes.Post("/register/questions/_reload", ReloadQuestions)
	}

	// account management debug only
	routes.Post("/debug/register", RegisterDebug)
	routes.Post("/debug/register/_batch", RegisterDebugInBatch)

	// user info
	routes.Get("/users/me", GetCurrentUser)
	routes.Get("/users/admin", ListAdmin)
	routes.Get("/users/:id", GetUserByID)
	routes.Get("/users", ListUsers)
	routes.Put("/users/:id", ModifyUser)
	routes.Patch("/users/:id<int>/_webvpn", ModifyUser)

	// shamir
	routes.Get("/shamir/status", GetShamirStatus)
	routes.Get("/shamir/:id", GetPGPMessageByUserID)
	routes.Get("/shamir", ListPGPMessages)
	routes.Post("/shamir/shares", UploadAllShares)
	routes.Post("/shamir/key", UploadPublicKey)
	routes.Post("/shamir/update", UpdateShamir)
	routes.Put("/shamir/refresh", RefreshShamir)
	routes.Patch("/shamir/refresh/_webvpn", RefreshShamir)
	routes.Post("/shamir/decrypt", UploadUserShares)
	routes.Get("/shamir/decrypt/:id", GetDecryptedUserEmail)
	routes.Get("/shamir/decrypt/status/:id", GetDecryptStatusbyUserID)
}
