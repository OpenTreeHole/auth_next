package apis

import (
	"auth_next/config"
	"auth_next/models"
	"auth_next/utils"
	"auth_next/utils/auth"
	"auth_next/utils/kong"
	"auth_next/utils/shamir"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	ok := auth.CheckVerificationCode(body.Email, scope, string(body.Verification))
	if !ok {
		return utils.BadRequest("验证码错误，请多次尝试或者重新获取验证码")
	}

	registered, err := models.HasRegisteredEmail(models.DB, body.Email)
	if err != nil {
		return err
	}
	deleted, err := models.HasDeletedEmail(models.DB, body.Email)
	if err != nil {
		return err
	}

	var user models.User
	if registered {
		if deleted {
			err = models.DB.Transaction(func(tx *gorm.DB) error {
				err = tx.Clauses(clause.Locking{Strength: "UPDATE"}).
					Where("identifier = ?", auth.MakeIdentifier(body.Email)).
					Take(&user).Error
				if err != nil {
					return err
				}

				user.IsActive = true
				user.Password, err = auth.MakePassword(body.Password)
				if err != nil {
					return err
				}

				err = tx.Save(&user).Error
				if err != nil {
					return err
				}

				return models.DeleteDeletedEmail(tx, body.Email)
			})
			if err != nil {
				return err
			}
		} else {
			return utils.BadRequest("该用户已注册，如果忘记密码，请使用忘记密码功能找回")
		}
	} else {
		user.Identifier = auth.MakeIdentifier(body.Email)
		user.Password, err = auth.MakePassword(body.Password)
		if err != nil {
			return err
		}

		err = models.DB.Transaction(func(tx *gorm.DB) error {
			err = tx.Create(&user).Error
			if err != nil {
				return err
			}

			err = models.AddRegisteredEmail(tx, body.Email)
			if err != nil {
				return err
			}

			// create shamir emails
			shares, err := shamir.Encrypt(body.Email, 7, 4)
			if err != nil {
				return err
			}

			return models.CreateShamirEmails(tx, user.ID, shares)
		})
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
	scope := "reset"
	var body RegisterRequest
	err := utils.ValidateBody(c, &body)
	if err != nil {
		return err
	}
	ok := auth.CheckVerificationCode(body.Email, scope, string(body.Verification))
	if !ok {
		return utils.BadRequest("验证码错误，请多次尝试或者重新获取验证码")
	}

	var user models.User
	err = models.DB.Transaction(func(tx *gorm.DB) error {
		err = tx.
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("identifier = ?", auth.MakeIdentifier(body.Email)).
			Take(&user).Error
		if err != nil {
			return err
		}

		user.IsActive = true
		user.Password, err = auth.MakePassword(body.Password)
		if err != nil {
			return err
		}
		return tx.Save(&user).Error
	})
	if err != nil {
		return err
	}

	err = kong.DeleteJwtCredential(user.ID)
	if err != nil {
		return err
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
		Message: "reset password successful",
	})
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
	email := c.Query("email")
	return verifyWithEmail(c, email)
}

func verifyWithEmail(c *fiber.Ctx, email string) error {
	if !utils.ValidateEmail(email) {
		return utils.BadRequest("email invalid")
	}
	err := utils.ValidateEmailFudan(email)
	if err != nil {
		return err
	}
	registered, err := models.HasRegisteredEmail(models.DB, email)
	if err != nil {
		return err
	}
	deleted, err := models.HasDeletedEmail(models.DB, email)
	if err != nil {
		return err
	}

	var scope string
	if !registered || deleted {
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
	var query ApikeyRequest
	err := utils.ValidateQuery(c, &query)
	if err != nil {
		return err
	}

	scope := "register"
	if !auth.CheckApikey(query.Apikey) {
		return utils.Forbidden("API Key 不正确，您可以选择使用旦夕账号登录，或者在 auth.fduhole.com 注册旦夕账户")
	}
	ok, err := models.HasRegisteredEmail(models.DB, query.Email)
	if err != nil {
		return err
	}

	if ok {
		return c.Status(409).JSON(utils.Message("用户已注册"))
	}
	if query.CheckRegister {
		return c.Status(200).JSON(utils.Message("用户未注册"))
	}

	code, err := auth.SetVerificationCode(query.Email, scope)
	if err != nil {
		return err
	}

	return c.JSON(ApikeyResponse{
		EmailVerifyResponse: EmailVerifyResponse{
			Message: "验证成功",
			Scope:   scope,
		},
		Code: code,
	})
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
	var body LoginRequest
	err := utils.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	var user models.User
	err = models.DB.Transaction(func(tx *gorm.DB) error {
		err = tx.
			Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("identifier = ?", auth.MakeIdentifier(body.Email)).
			Take(&user).Error
		if err != nil {
			return err
		}

		ok, err := auth.CheckPassword(body.Password, user.Password)
		if err != nil {
			return err
		}
		if !ok {
			return utils.Forbidden("密码错误")
		}

		user.IsActive = false
		err = tx.Save(&user).Error
		if err != nil {
			return err
		}

		return models.AddDeletedEmail(tx, body.Email)
	})

	err = kong.DeleteJwtCredential(user.ID)
	if err != nil {
		return err
	}

	return c.SendStatus(204)
}
