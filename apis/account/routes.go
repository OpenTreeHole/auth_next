package account

import "github.com/gofiber/fiber/v2"

func RegisterRoutes(routes fiber.Router) {
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
}
