package account

import (
	. "auth_next/utils"
	"github.com/gofiber/fiber/v2"
)

// Login godoc
//
//	@Summary		Login an account
//	@Description	Login with email and password, return jwt token
//	@Tags			token
//	@Accept			json
//	@Produce		json
//	@Router			/login [post]
//	@Param			json	body		LoginRequest	true	"json"
//	@Success		200		{object}	TokenResponse
//	@Failure		400		{object}	MessageResponse
//	@Failure		404		{object}	MessageResponse	"User Not Found"
//	@Failure		500		{object}	MessageResponse
func Login(c *fiber.Ctx) error {
	var _ LoginRequest
	return c.JSON(TokenResponse{Message: "Login successful"})
}

// Logout
//
//	@Summary		Logout
//	@Description	Logout, clear jwt credential and return successful message
//	@Tags			token
//	@Produce		json
//	@Router			/logout [get]
//	@Success		200	{object}	MessageResponse
func Logout(c *fiber.Ctx) error {
	return c.JSON(Message("logout successful"))
}

// Refresh
//
//	@Summary	Refresh jwt token
//	@Tags		token
//	@Produce	json
//	@Router		/refresh [post]
//	@Success	200	{object}	TokenResponse
func Refresh(c *fiber.Ctx) error {
	return c.JSON(TokenResponse{Message: "refresh successful"})
}
