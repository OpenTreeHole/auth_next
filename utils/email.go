package utils

import (
	"auth_next/config"
	"github.com/jordan-wright/email"
	"net/smtp"
	"strconv"
)

func SendEmail(subject, content string, receiver []string) error {
	e := &email.Email{
		To:      receiver,
		From:    config.Config.EmailUsername,
		Subject: subject,
		Text:    []byte(content),
	}

	return e.SendWithTLS(
		config.Config.EmailHost+strconv.Itoa(config.Config.EmailPort),
		smtp.PlainAuth("", config.Config.EmailUsername, config.Config.EmailPassword, config.Config.EmailHost),
		nil,
	)
}
