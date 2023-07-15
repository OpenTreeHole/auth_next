package apis

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"
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
	routes.Delete("/users/me", DeleteUser)

	// account management debug only
	routes.Post("/debug/register", RegisterDebug)
	routes.Post("/debug/register/_batch", RegisterDebugInBatch)

	// user info
	routes.Get("/users/me", GetCurrentUser)
	routes.Get("/users/admin", ListAdmin)
	routes.Get("/users/:id", GetUserByID)
	routes.Get("/users", ListUsers)
	routes.Put("/users/:id", ModifyUser)

	// shamir
	routes.Get("/shamir/status", GetShamirStatus)
	routes.Get("/shamir/:id", GetPGPMessageByUserID)
	routes.Get("/shamir", ListPGPMessages)
	routes.Post("/shamir/shares", UploadAllShares)
	routes.Post("/shamir/key", UploadPublicKey)
	routes.Post("/shamir/update", UpdateShamir)
	routes.Put("/shamir/refresh", RefreshShamir)
}
