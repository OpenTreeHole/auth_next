package apis

import (
	"auth_next/config"
	"auth_next/models"
	"auth_next/utils"
	"auth_next/utils/auth"
	"auth_next/utils/kong"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"time"
)

// Register godoc
//
//	@Summary		register
//	@Description	register with email, password and verification code
//	@Tags			account
//	@Accept			json
//	@Produce		json
//	@Router			/register [post]
//	@Param			json	body		RegisterRequest	true	"json"
//	@Success		201		{object}	TokenResponse
//	@Failure		400		{object}	utils.MessageResponse	"验证码错误、用户已注册"
//	@Failure		500		{object}	utils.MessageResponse
func Register(c *fiber.Ctx) error {
	scope := "register"
	var body RegisterRequest
	err := utils.ValidateBody(c, &body)
	if err != nil {
		return err
	}
	ok, err := auth.CheckVerificationCode(body.Email, scope, body.Verification)
	if err != nil {
		return err
	}
	if !ok {
		return utils.BadRequest("验证码错误")
	}

	registered := models.HasRegisteredEmail(body.Email)
	deleted := models.HasDeletedEmail(body.Email)

	var user models.User
	if registered {
		if !deleted {
			return utils.BadRequest("该用户已注册，如果忘记密码，请使用忘记密码功能找回")
		} else {
			identifier := auth.MakeIdentifier(body.Email)

			err = models.DB.Find(&user, "identifier = ?", identifier).Error
			if err != nil {
				return err
			}

			user.IsActive = true
			user.Password, err = auth.MakePassword(body.Password)
			user.LastLogin = time.Now()
			if err != nil {
				return err
			}

			err = models.DB.Save(&user).Error
			if err != nil {
				return err
			}

			err = models.DeleteDeletedEmail(body.Email)
		}
	} else {
		user = models.User{
			Identifier: auth.MakeIdentifier(body.Email),
			Password:   "",
			JoinedTime: time.Now().In(config.Config.TZLocation),
			LastLogin:  time.Now().In(config.Config.TZLocation),
		}
		err = models.DB.Create(&user).Error
		if err != nil {
			return err
		}

		err = models.AddRegisteredEmail(body.Email)
		if err != nil {
			return err
		}

		err = kong.CreateUser(user.ID)
		if err != nil {
			return err
		}
	}

	accessToken, refreshToken, err := kong.CreateToken(&user)
	if err != nil {
		return err
	}

	err = auth.DeleteVerificationCode(body.Email, scope)
	if err != nil {
		return err
	}
	return c.JSON(TokenResponse{
		Access:  accessToken,
		Refresh: refreshToken,
		Message: "register successful",
	})
}

// ChangePassword godoc
//
//	@Summary		reset password
//	@Description	reset password, reset jwt credential
//	@Tags			account
//	@Accept			json
//	@Produce		json
//	@Router			/register [put]
//	@Param			json	body		RegisterRequest	true	"json"
//	@Success		200		{object}	TokenResponse
//	@Failure		400		{object}	utils.MessageResponse	"验证码错误"
//	@Failure		500		{object}	utils.MessageResponse
func ChangePassword(c *fiber.Ctx) error {
	return c.JSON(TokenResponse{Message: "reset password successful"})
}

// VerifyWithEmailOld godoc
//
//	@Summary		verify with email in path
//	@Description	verify with email in path, send verification email
//	@Deprecated
//	@Tags		account
//	@Produce	json
//	@Router		/verify/email/{email} [get]
//	@Param		email	path		string	true	"email"
//	@Success	200		{object}	EmailVerifyResponse
//	@Failure	400		{object}	utils.MessageResponse	“email不在白名单中”
//	@Failure	500		{object}	utils.MessageResponse
func VerifyWithEmailOld(c *fiber.Ctx) error {
	email := c.Params("email")
	return verifyWithEmail(c, email)
}

// VerifyWithEmail godoc
//
//	@Summary		verify with email in query
//	@Description	verify with email in query, Send verification email
//	@Tags			account
//	@Produce		json
//	@Router			/verify/email [get]
//	@Param			email	query		string	true	"email"
//	@Success		200		{object}	EmailVerifyResponse
//	@Failure		400		{object}	utils.MessageResponse
//	@Failure		403		{object}	utils.MessageResponse	“email不在白名单中”
//	@Failure		500		{object}	utils.MessageResponse
func VerifyWithEmail(c *fiber.Ctx) error {
	email := c.Params("email")
	return verifyWithEmail(c, email)
}

func verifyWithEmail(c *fiber.Ctx, email string) error {
	if !utils.ValidateEmail(email) {
		return utils.BadRequest("email invalid")
	}
	registered := models.HasRegisteredEmail(email)
	var scope string
	if !registered {
		scope = "register"
	} else {
		scope = "reset"
	}
	code, err := auth.SetVerificationCode(email, scope)
	if err != nil {
		return err
	}

	baseContent := fmt.Sprintf(`
您的验证码是: %v
验证码的有效期为 %d 分钟
如果您意外地收到了此邮件，请忽略它
`,
		code, config.Config.VerificationCodeExpires)

	var subject, content string
	if !registered {
		subject = fmt.Sprintf("%v 注册验证", config.Config.SiteName)
		content = fmt.Sprintf("欢迎注册 %v, %v", config.Config.SiteName, baseContent)
	} else {
		subject = fmt.Sprintf("%v 重置密码", config.Config.SiteName)
		content = fmt.Sprintf("您正在重置密码, %v", baseContent)
	}

	err = utils.SendEmail(subject, content, []string{email})
	if err != nil {
		return err
	}

	return c.JSON(EmailVerifyResponse{
		Message: "验证邮件已发送，请查收\n如未收到，请检查邮件地址是否正确，检查垃圾箱，或重试",
		Scope:   scope,
	})
}

// VerifyWithApikey godoc
//
//	@Summary		verify with email in query and apikey
//	@Description	verify with email in query, return verification code
//	@Tags			account
//	@Produce		json
//	@Router			/verify/apikey [get]
//	@Param			email	query		ApikeyRequest	true	"apikey, email"
//	@Success		200		{object}	ApikeyResponse
//	@Success		200		{object}	utils.MessageResponse	"用户未注册“
//	@Failure		403		{object}	utils.MessageResponse	"apikey不正确“
//	@Failure		409		{object}	utils.MessageResponse	"用户已注册“
//	@Failure		500		{object}	utils.MessageResponse
func VerifyWithApikey(c *fiber.Ctx) error {
	return c.JSON(nil)
}

// DeleteUser godoc
//
//	@Summary		delete user
//	@Description	delete user and related jwt credentials
//	@Tags			account
//	@Router			/users/me [delete]
//	@Param			json	body	LoginRequest	true	"email, password"
//	@Success		204
//	@Failure		400	{object}	utils.MessageResponse	"密码错误“
//	@Failure		404	{object}	utils.MessageResponse	"用户不存在“
//	@Failure		500	{object}	utils.MessageResponse
func DeleteUser(c *fiber.Ctx) error {
	return c.SendStatus(204)
}
