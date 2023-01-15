package apis

import "github.com/gofiber/fiber/v2"

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
//	@Failure		400		{object}	utils.MessageResponse	"验证码错误、用户已注册“
//	@Failure		500		{object}	utils.MessageResponse
func Register(c *fiber.Ctx) error {
	return c.JSON(TokenResponse{Message: "register successful"})
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
//	@Failure		400		{object}	utils.MessageResponse	"验证码错误“
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
	return c.JSON(EmailVerifyResponse{Message: "验证邮件已发送，请查收\n如未收到，请检查邮件地址是否正确，检查垃圾箱，或重试"})
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
	return c.JSON(nil)
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
