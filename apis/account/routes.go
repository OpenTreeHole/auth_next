package account

import "github.com/gofiber/fiber/v2"

func RegisterRoutes(routes fiber.Router) {
	routes.Post("/login", Login)
	routes.Get("/logout", Logout)
	routes.Post("/refresh", Refresh)
}
