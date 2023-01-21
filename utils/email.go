package utils

import (
	"auth_next/config"
	"crypto/tls"
	"github.com/jordan-wright/email"
	"net/smtp"
)

func SendEmail(subject, content string, receiver []string) error {
	emailUsername := config.Config.EmailServerNoReplyUrl.User.Username() + "@" + config.Config.EmailDomain
	emailPassword, _ := config.Config.EmailServerNoReplyUrl.User.Password()
	e := &email.Email{
		To:      receiver,
		From:    emailUsername,
		Subject: subject,
		Text:    []byte(content),
	}

	return e.SendWithTLS(
		config.Config.EmailServerNoReplyUrl.Host,
		smtp.PlainAuth(
			"",
			emailUsername,
			emailPassword,
			config.Config.EmailServerNoReplyUrl.Hostname(),
		),
		&tls.Config{
			ServerName: config.Config.EmailServerNoReplyUrl.Hostname(),
		},
	)
}
