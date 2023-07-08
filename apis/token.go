package apis

import (
	. "auth_next/models"
	"auth_next/utils/auth"
	"auth_next/utils/kong"
	"auth_next/utils/shamir"
	"github.com/gofiber/fiber/v2"
	"github.com/opentreehole/go-common"
)

var ErrLogin = common.Forbidden("邮箱或密码错误")

// Login godoc
//
//	@Summary		Login
//	@Description	Login with email and password, return jwt token, not need jwt
//	@Tags			token
//	@Accept			json
//	@Produce		json
//	@Router			/login [post]
//	@Param			json	body		LoginRequest	true	"json"
//	@Success		200		{object}	TokenResponse
//	@Failure		400		{object}	common.MessageResponse
//	@Failure		404		{object}	common.MessageResponse	"User Not Found"
//	@Failure		500		{object}	common.MessageResponse
func Login(c *fiber.Ctx) error {
	var body LoginRequest
	err := common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	var user User
	err = DB.
		Where("identifier = ? AND is_active = true", auth.MakeIdentifier(body.Email)).
		Take(&user).Error
	if err != nil {
		return ErrLogin
	}

	ok, err := auth.CheckPassword(body.Password, user.Password)
	if err != nil {
		return err
	}
	if !ok {
		return ErrLogin
	}

	// if no shamir email, insert it
	var hasShamir int64
	err = DB.Model(&ShamirEmail{}).Where("user_id = ?", user.ID).Count(&hasShamir).Error
	if err != nil {
		return err
	}
	if hasShamir == 0 {
		shares, err := shamir.Encrypt(body.Email, 7, 4)
		if err != nil {
			return err
		}

		err = CreateShamirEmails(DB, user.ID, shares)
		if err != nil {
			return err
		}
	}

	access, refresh, err := user.CreateJWTToken()
	if err != nil {
		return err
	}

	// update login time
	err = DB.Model(&user).Select("LastLogin").Updates(&user).Error
	if err != nil {
		return err
	}

	return c.JSON(TokenResponse{
		Access:  access,
		Refresh: refresh,
		Message: "Login successful",
	})
}

// Logout
//
//	@Summary		Logout
//	@Description	Logout, clear jwt credential and return successful message, logout, jwt needed
//	@Tags			token
//	@Produce		json
//	@Router			/logout [get]
//	@Success		200	{object}	common.MessageResponse
func Logout(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(int)
	if !ok {
		return common.Unauthorized()
	}

	_, err := LoadUserFromDB(userID)
	if err != nil {
		return err
	}

	err = kong.DeleteJwtCredential(userID)
	if err != nil {
		return err
	}

	return c.JSON(common.Message("logout successful"))
}

// Refresh
//
//	@Summary		Refresh jwt token
//	@Description	Refresh jwt token with refresh token in header, login required
//	@Tags			token
//	@Produce		json
//	@Router			/refresh [post]
//	@Success		200	{object}	TokenResponse
func Refresh(c *fiber.Ctx) error {
	refreshToken, user, err := GetUserByRefreshToken(c)
	if err != nil {
		return err
	}

	// update login time
	err = DB.Model(&user).Select("LastLogin").Updates(&user).Error
	if err != nil {
		return err
	}

	access, _, err := user.CreateJWTToken()
	if err != nil {
		return err
	}

	return c.JSON(TokenResponse{
		Access:  access,
		Refresh: refreshToken, // using old refreshToken instead
		Message: "refresh successful",
	})
}
