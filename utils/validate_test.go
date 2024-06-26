package utils

import (
	"fmt"
	"github.com/opentreehole/go-common"
	"testing"

	"github.com/go-playground/assert/v2"

	"auth_next/config"
)

func TestValidateEmail(t *testing.T) {
	config.Config.EmailWhitelist = []string{"fudan.edu.cn", "m.fudan.edu.cn"}
	assert.Equal(t, ValidateEmail("abcd@fudan.edu.cn"), true)
	assert.Equal(t, ValidateEmail("abcd@qq.com"), false)
	assert.Equal(t, ValidateEmail("123345"), false)
}

func TestValidateEmailFudan(t *testing.T) {
	fmt.Println(ValidateEmailFudan("21307130001@m.fudan.edu.cn"))
	fmt.Println(ValidateEmailFudan("21307130001@fudan.edu.cn"))
	fmt.Println(ValidateEmailFudan("20307130001@m.fudan.edu.cn"))
	fmt.Println(ValidateEmailFudan("20307130001@fudan.edu.cn"))
	fmt.Println(ValidateEmailFudan("abcd@fudan.edu.cn"))
}

func TestValidateAll(t *testing.T) {
	type TempStruct struct {
		Email string `validate:"isValidEmail"`
	}
	config.Config.EmailWhitelist = []string{"fudan.edu.cn", "m.fudan.edu.cn"}
	err := common.ValidateStruct(TempStruct{Email: "abcd@fudan.edu.cn"})
	assert.Equal(t, err, nil)
}
