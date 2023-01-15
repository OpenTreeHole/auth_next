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
	routes.Get("/verify/email/{email}", VerifyWithEmailOld)
	routes.Get("/verify/apikey", VerifyWithApikey)
	routes.Post("/register", Register)
	routes.Put("/register", ChangePassword)
	routes.Delete("/users/me", DeleteUser)

	// user info
	routes.Get("/users/me", GetCurrentUser)
	routes.Get("/users/{id}", GetUserByID)
	routes.Get("/users", ListUsers)
	routes.Put("/users/me", ModifyUser)
}
