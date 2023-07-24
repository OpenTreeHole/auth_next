package apis

import (
	"github.com/gofiber/fiber/v2"
	"github.com/opentreehole/go-common"

	. "auth_next/models"
)

// GetCurrentUser godoc
//
//	@Summary		get current user
//	@Description	get user by verifying user token or header
//	@Tags			user
//	@Produce		json
//	@Router			/users/me [get]
//	@Success		200	{object}	User
//	@Failure		404	{object}	common.MessageResponse	"用户不存在"
//	@Failure		500	{object}	common.MessageResponse
func GetCurrentUser(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(int)
	if !ok {
		return common.Unauthorized()
	}
	user, err := LoadUserFromDB(userID)
	if err != nil {
		return err
	}
	return c.JSON(&user)
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
//	@Failure		403		{object}	common.MessageResponse	"不是该用户或管理员"
//	@Failure		404		{object}	common.MessageResponse	"用户不存在"
//	@Failure		500		{object}	common.MessageResponse
func GetUserByID(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(int)
	if !ok {
		return common.Unauthorized()
	}

	toUserId, err := c.ParamsInt("id")
	if err != nil {
		return err
	}
	if !(toUserId == userID || IsAdmin(userID)) {
		return common.Forbidden()
	}

	user, err := LoadUserFromDB(toUserId)
	if err != nil {
		return err
	}
	return c.JSON(user)
}

// ListUsers godoc
//
//	@Summary		list all users
//	@Description	list all users, admin only, not implemented
//	@Tags			user
//	@Produce		json
//	@Router			/users [get]
//	@Success		200		{array}		User
//	@Failure		403		{object}	common.MessageResponse	"不是管理员"
//	@Failure		500		{object}	common.MessageResponse
func ListUsers(c *fiber.Ctx) error {
	return c.JSON([]User{})
}

// ListAdmin godoc
//
//	@Summary		list admins
//	@Tags			user
//	@Produce		json
//	@Router			/users/admin [get]
//	@Success		200		{array}		int
//	@Failure		500		{object}	common.MessageResponse
func ListAdmin(c *fiber.Ctx) error {
	return c.JSON(AdminIDList.Load().([]int))
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
//	@Failure		403		{object}	common.MessageResponse	"不是管理员"
//	@Failure		500		{object}	common.MessageResponse
func ModifyUser(c *fiber.Ctx) error {
	var body ModifyUserRequest
	err := common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	if body.Nickname == nil {
		return common.BadRequest("无效请求")
	}

	userID, ok := c.Locals("user_id").(int)
	if !ok {
		return common.Unauthorized()
	}

	toUserID, err := c.ParamsInt("id")
	if err != nil {
		return err
	}

	if !(IsAdmin(userID) || userID == toUserID) {
		return common.Forbidden()
	}
	user, err := LoadUserFromDB(toUserID)
	if err != nil {
		return err
	}

	user.Nickname = *body.Nickname

	err = DB.Model(&user).Omit("LastLogin").Updates(&user).Error
	if err != nil {
		return err
	}

	return c.Status(201).JSON(user)
}
