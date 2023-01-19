package utils

import (
	"auth_next/config"
	"github.com/go-playground/assert/v2"
	"testing"
)

func TestValidateEmail(t *testing.T) {
	config.Config.EmailWhitelist = []string{"fudan.edu.cn", "m.fudan.edu.cn"}
	assert.Equal(t, ValidateEmail("abcd@fudan.edu.cn"), true)
	assert.Equal(t, ValidateEmail("abcd@qq.com"), false)
	assert.Equal(t, ValidateEmail("123345"), false)
}
