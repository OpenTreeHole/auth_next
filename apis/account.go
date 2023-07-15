package apis

import (
	"auth_next/config"
	. "auth_next/models"
	"auth_next/utils"
	"auth_next/utils/auth"
	"auth_next/utils/kong"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/opentreehole/go-common"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"runtime"
)

// Register godoc
//
// @Summary register
// @Description register with email, password and verification code
// @Tags account
// @Accept json
// @Produce json
// @Router /register [post]
// @Param json body RegisterRequest true "json"
// @Success 201 {object} TokenResponse
// @Failure 400 {object} common.MessageResponse "验证码错误、用户已注册"
// @Failure 500 {object} common.MessageResponse
func Register(c *fiber.Ctx) (err error) {
	scope := "register"
	var body RegisterRequest
	err = common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	// check verification code
	ok := auth.CheckVerificationCode(body.Email, scope, string(body.Verification))
	if !ok {
		return common.BadRequest("验证码错误，请多次尝试或者重新获取验证码")
	}

	defer func() {
		// delete verification code if register success
		if err == nil {
			err = auth.DeleteVerificationCode(body.Email, scope)
		}
	}()

	err = register(c, body.Email, body.Password, false)
	return err
}

// RegisterDebug godoc
//
// @Summary register, debug only
// @Description register with email, password, not need verification code
// @Tags account
// @Accept json
// @Produce json
// @Router /debug/register [post]
// @Param json body LoginRequest true "json"
// @Success 201 {object} TokenResponse
// @Failure 400 {object} common.MessageResponse "用户已注册"
// @Failure 500 {object} common.MessageResponse
// @Security ApiKeyAuth
func RegisterDebug(c *fiber.Ctx) (err error) {
	var body LoginRequest
	err = common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	return register(c, body.Email, body.Password, false)
}

// RegisterDebugInBatch godoc
//
// @Summary register in batch, debug only
// @Description register with email, password, not need verification code
// @Tags account
// @Accept json
// @Produce json
// @Router /debug/register/_batch [post]
// @Param json object RegisterInBatchRequest true "json"
// @Success 201 {object} TokenResponse
// @Failure 400 {object} common.MessageResponse "用户已注册"
// @Failure 500 {object} common.MessageResponse
// @Security ApiKeyAuth
func RegisterDebugInBatch(c *fiber.Ctx) (err error) {
	const taskScope = "register_in_batch"
	log.Info().Str("scope", taskScope).Msg("register in batch")

	var body RegisterInBatchRequest
	err = common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	// check registered
	var emailHashes []string
	for _, data := range body.Data {
		emailHashes = append(emailHashes, Sha3SumEmail(data.Email))
	}

	var count int64
	err = DB.Model(&RegisteredEmail{}).Where("hash IN ?", emailHashes).Count(&count).Error
	if err != nil {
		return err
	}

	if count > 0 {
		return common.BadRequest("用户已注册")
	}

	err = DB.Session(&gorm.Session{
		NewDB:             true,
		AllowGlobalUpdate: true,
		CreateBatchSize:   1000,
	}).Transaction(func(tx *gorm.DB) (err error) {
		// create users
		var users []User

		// channels
		var tasksChan = make(chan func(), 100)
		var userResultChan = make(chan User, 100)
		var errChan = make(chan error, 100)

		defer func() {
			close(tasksChan)
			close(userResultChan)
			close(errChan)
		}()

		// task executor
		for i := 0; i < runtime.NumCPU(); i++ {
			go func() {
				for task := range tasksChan {
					task()
				}
			}()
		}

		// task sender
		go func() {
			for _, data := range body.Data {
				data := data
				tasksChan <- func() {
					var user User
					user.Email = data.Email
					user.Identifier = auth.MakeIdentifier(data.Email)
					user.Password, err = auth.MakePassword(data.Password)
					if err != nil {
						errChan <- err
						return
					}
					userResultChan <- user
				}
				if len(errChan) > 0 {
					return
				}
			}
		}()

		// receive task result
		for range body.Data {
			users = append(users, <-userResultChan)
			if len(errChan) > 0 {
				return <-errChan
			}
			if len(users)%1000 == 0 {
				log.Info().Str("scope", taskScope).Msgf("prepare users: %d", len(users))
			}
		}

		if len(errChan) > 0 {
			return <-errChan
		}

		err = tx.Create(&users).Error
		if err != nil {
			return err
		}

		log.Info().Str("scope", taskScope).Msgf("create users: %d", len(users))

		// create registered emails
		var registeredEmails []RegisteredEmail
		for _, hash := range emailHashes {
			registeredEmails = append(registeredEmails, RegisteredEmail{
				Hash: hash,
			})
		}

		err = tx.Create(&registeredEmails).Error
		if err != nil {
			return err
		}

		log.Info().Str("scope", taskScope).Msgf("create registered emails: %d", len(registeredEmails))

		if config.Config.ShamirFeature {

			// create shamir emails
			var shamirEmailResultChan = make(chan []ShamirEmail, 100)
			defer close(shamirEmailResultChan)

			var shamirEmails []ShamirEmail

			// task sender
			go func() {
				for _, user := range users {
					user := user
					tasksChan <- func() {
						innerShamirEmails, err := GenerateShamirEmails(user.ID, user.Email)
						if err != nil {
							errChan <- err
						}
						shamirEmailResultChan <- innerShamirEmails
					}
					if len(errChan) > 0 {
						return
					}
				}
			}()

			// receive task result
			for range users {
				select {
				case err = <-errChan:
					return err
				case innerShamirEmails := <-shamirEmailResultChan:
					shamirEmails = append(shamirEmails, innerShamirEmails...)
				}
				if len(shamirEmails)%1000 == 0 {
					log.Info().Str("scope", taskScope).Msgf("prepare shamir emails: %d", len(shamirEmails))
				}
			}

			// create shamir emails in batch
			err = tx.Create(&shamirEmails).Error
			if err != nil {
				return err
			}

			log.Info().Str("scope", taskScope).Msgf("create shamir emails: %d", len(shamirEmails))
		}

		// create kong consumer
		if !config.Config.Standalone {
			for _, user := range users {
				err = kong.CreateUser(user.ID)
				if err != nil {
					return err
				}
			}

			log.Info().Str("scope", taskScope).Msgf("create kong consumers: %d", len(users))
		}

		return nil
	})

	if err != nil {
		return err
	}

	return c.JSON(common.MessageResponse{
		Message: "register successful",
	})
}

func register(c *fiber.Ctx, email, password string, batch bool) error {
	registered, err := HasRegisteredEmail(DB, email)
	if err != nil {
		return err
	}
	deleted, err := HasDeletedEmail(DB, email)
	if err != nil {
		return err
	}

	var user User
	if registered {
		if deleted {
			return common.BadRequest("注销账号后禁止注册")
		} else {
			return common.BadRequest("该用户已注册，如果忘记密码，请使用忘记密码功能找回")
		}
	}

	// not registered

	user.Identifier = auth.MakeIdentifier(email)
	user.Password, err = auth.MakePassword(password)
	if err != nil {
		return err
	}

	err = DB.Transaction(func(tx *gorm.DB) error {
		err = tx.Create(&user).Error
		if err != nil {
			return err
		}

		err = AddRegisteredEmail(tx, email)
		if err != nil {
			return err
		}

		// create shamir emails
		if config.Config.ShamirFeature {
			return CreateShamirEmails(tx, user.ID, email)
		}

		if !config.Config.Standalone {
			err = kong.CreateUser(user.ID)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	accessToken, refreshToken, err := user.CreateJWTToken()
	if err != nil {
		return err
	}

	if !batch {
		return c.JSON(TokenResponse{
			Access:  accessToken,
			Refresh: refreshToken,
			Message: "register successful",
		})
	}
	return nil
}

// ChangePassword godoc
//
// @Summary reset password
// @Description reset password, reset jwt credential
// @Tags account
// @Accept json
// @Produce json
// @Router /register [put]
// @Param json body RegisterRequest true "json"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} common.MessageResponse "验证码错误"
// @Failure 500 {object} common.MessageResponse
func ChangePassword(c *fiber.Ctx) error {
	scope := "reset"
	var body RegisterRequest
	err := common.ValidateBody(c, &body)
	if err != nil {
		return err
	}
	ok := auth.CheckVerificationCode(body.Email, scope, string(body.Verification))
	if !ok {
		return common.BadRequest("验证码错误，请多次尝试或者重新获取验证码")
	}

	var user User
	err = DB.Transaction(func(tx *gorm.DB) error {
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

	if !config.Config.Standalone {
		err = kong.DeleteJwtCredential(user.ID)
		if err != nil {
			return err
		}
	}

	accessToken, refreshToken, err := user.CreateJWTToken()
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
// @Summary verify with email in path
// @Description verify with email in path, send verification email
// @Deprecated
// @Tags account
// @Produce json
// @Router /verify/email/{email} [get]
// @Param email path string true "email"
// @Param scope query string false "scope"
// @Success 200 {object} EmailVerifyResponse
// @Failure 400 {object} common.MessageResponse “email不在白名单中”
// @Failure 500 {object} common.MessageResponse
func VerifyWithEmailOld(c *fiber.Ctx) error {
	email := c.Params("email")
	scope := c.Query("scope")
	return verifyWithEmail(c, email, scope)
}

// VerifyWithEmail godoc
//
// @Summary verify with email in query
// @Description verify with email in query, Send verification email
// @Tags account
// @Produce json
// @Router /verify/email [get]
// @Param email query string true "email"
// @Param scope query string false "scope"
// @Success 200 {object} EmailVerifyResponse
// @Failure 400 {object} common.MessageResponse
// @Failure 403 {object} common.MessageResponse “email不在白名单中”
// @Failure 500 {object} common.MessageResponse
func VerifyWithEmail(c *fiber.Ctx) error {
	email := c.Query("email")
	scope := c.Query("scope")
	return verifyWithEmail(c, email, scope)
}

func verifyWithEmail(c *fiber.Ctx, email, givenScope string) error {
	if !utils.ValidateEmail(email) {
		return common.BadRequest("email invalid")
	}
	err := utils.ValidateEmailFudan(email)
	if err != nil {
		return err
	}
	deleted, err := HasDeletedEmail(DB, email)
	if err != nil {
		return err
	}
	if deleted {
		return common.BadRequest("注销账号后禁止注册")
	}
	registered, err := HasRegisteredEmail(DB, email)
	if err != nil {
		return err
	}

	var scope string
	if !registered {
		scope = "register"
	} else {
		scope = "reset"
	}
	if givenScope == "register" && scope == "reset" {
		return common.BadRequest("该用户已注册，请使用重置密码功能")
	} else if givenScope == "reset" && scope == "register" {
		return common.BadRequest("该用户未注册，请先注册账户")
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
// @Summary verify with email in query and apikey
// @Description verify with email in query, return verification code
// @Tags account
// @Produce json
// @Router /verify/apikey [get]
// @Param email query ApikeyRequest true "apikey, email"
// @Success 200 {object} ApikeyResponse
// @Success 200 {object} common.MessageResponse "用户未注册"
// @Failure 403 {object} common.MessageResponse "apikey不正确"
// @Failure 409 {object} common.MessageResponse "用户已注册"
// @Failure 500 {object} common.MessageResponse
func VerifyWithApikey(c *fiber.Ctx) error {
	if config.RegisterApikeySecret == "" {
		return common.Forbidden("API Key 注册已禁用")
	}

	var query ApikeyRequest
	err := common.ValidateQuery(c, &query)
	if err != nil {
		return err
	}

	scope := "register"
	if !auth.CheckApikey(query.Apikey) {
		return common.Forbidden("API Key 不正确，您可以选择使用旦夕账号登录，或者在 auth.fduhole.com 注册旦夕账户")
	}
	ok, err := HasRegisteredEmail(DB, query.Email)
	if err != nil {
		return err
	}

	if ok {
		return c.Status(409).JSON(common.HttpError{Code: 409, Message: "用户已注册"})
	}
	if query.CheckRegister {
		return c.Status(200).JSON(common.HttpError{Code: 200, Message: "用户已注册"})
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
// @Summary delete user
// @Description delete user and related jwt credentials
// @Tags account
// @Router /users/me [delete]
// @Param json body LoginRequest true "email, password"
// @Success 204
// @Failure 400 {object} common.MessageResponse "密码错误“
// @Failure 404 {object} common.MessageResponse "用户不存在“
// @Failure 500 {object} common.MessageResponse
func DeleteUser(c *fiber.Ctx) error {
	var body LoginRequest
	err := common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	var user User
	err = DB.Transaction(func(tx *gorm.DB) error {
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
			return common.Forbidden("密码错误")
		}

		user.IsActive = false
		err = tx.Save(&user).Error
		if err != nil {
			return err
		}

		return AddDeletedEmail(tx, body.Email)
	})

	err = kong.DeleteJwtCredential(user.ID)
	if err != nil {
		return err
	}

	return c.SendStatus(204)
}
