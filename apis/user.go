package apis

import (
	. "auth_next/models"
	"github.com/gofiber/fiber/v2"
)

// GetCurrentUser godoc
//
//	@Summary		get current user
//	@Description	get user by verifying user token or header
//	@Tags			user
//	@Produce		json
//	@Router			/users/me [get]
//	@Success		200	{object}	User
//	@Failure		404	{object}	utils.MessageResponse	"用户不存在"
//	@Failure		500	{object}	utils.MessageResponse
func GetCurrentUser(c *fiber.Ctx) error {
	return c.JSON(User{})
}

// GetUserByID godoc
//
//	@Summary		get user by id
//	@Description	get user by id in path, owner or admin
//	@Tags			user
//	@Produce		json
//	@Router			/users/{user_id} [get]
//	@Param			user_id	path		int	true	"UserID"
//	@Success		200		{object}	User
//	@Failure		403		{object}	utils.MessageResponse	"不是该用户或管理员"
//	@Failure		404		{object}	utils.MessageResponse	"用户不存在"
//	@Failure		500		{object}	utils.MessageResponse
func GetUserByID(c *fiber.Ctx) error {
	return c.JSON(User{})
}

// ListUsers godoc
//
//	@Summary		list all users
//	@Description	list all users, admin only
//	@Tags			user
//	@Produce		json
//	@Router			/users [get]
//	@Param			user_id	path		int	true	"UserID"
//	@Success		200		{array}		User
//	@Failure		403		{object}	utils.MessageResponse	"不是管理员"
//	@Failure		500		{object}	utils.MessageResponse
func ListUsers(c *fiber.Ctx) error {
	return c.JSON([]User{})
}

// ModifyUser godoc
//
//	@Summary		modify user
//	@Description	modify user, owner or admin
//	@Tags			user
//	@Produce		json
//	@Router			/users/{user_id} [put]
//	@Param			user_id	path		int	true	"UserID"
//	@Success		201		{object}	User
//	@Failure		403		{object}	utils.MessageResponse	"不是管理员"
//	@Failure		500		{object}	utils.MessageResponse
func ModifyUser(c *fiber.Ctx) error {
	return c.JSON(User{})
}
