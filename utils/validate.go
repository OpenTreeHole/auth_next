package utils

import (
	"auth_next/config"
	"github.com/go-playground/validator/v10"
	"github.com/opentreehole/go-common"
	"github.com/rs/zerolog/log"
	"strconv"
	"strings"
)

func init() {
	err := common.Validate.RegisterValidation("isValidEmail", ValidateEmailFunc, false)
	if err != nil {
		log.Fatal().Err(err).Msg("register validation failed")
	}
}

func ValidateEmail(email string) bool {
	emailSplit := strings.Split(email, "@")
	if len(emailSplit) != 2 {
		return false
	}
	if len(config.Config.EmailWhitelist) == 0 {
		return true
	}
	return InUnorderedSlice(config.Config.EmailWhitelist, emailSplit[1])
}

func ValidateEmailFudan(email string) error {
	year, err := strconv.Atoi(email[:2])
	if err != nil {
		return nil
	}
	emailSplit := strings.Split(email, "@")

	const messageSuffix = `如果您的邮箱不满足此规则，可以尝试邮箱别名，或发送您的学邮和情况说明到 dev@fduhole.com ，我们为您手动处理`

	if emailSplit[1] == "fudan.edu.cn" {
		if year >= 21 {
			return common.BadRequest("21级及以后的同学请使用m.fudan.edu.cn邮箱。" + messageSuffix)
		}
	} else if emailSplit[1] == "m.fudan.edu.cn" {
		if year <= 20 {
			return common.BadRequest("20级及以前的同学请使用fudan.edu.cn邮箱。" + messageSuffix)
		}
	}
	return nil
}

func ValidateEmailFunc(fl validator.FieldLevel) bool {
	return ValidateEmail(fl.Field().String())
}

func IsEmail(email string) bool {
	emailSplit := strings.Split(email, "@")
	return len(emailSplit) == 2
}
