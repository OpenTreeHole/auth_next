package utils

import (
	"auth_next/config"
	"crypto/tls"
	"github.com/jordan-wright/email"
	"github.com/opentreehole/go-common"
	"net/smtp"
)

func SendEmail(subject, content string, receiver []string) error {
	if config.Config.EmailServerNoReplyUrl.String() == "" {
		return common.InternalServerError("failed to send email: email_server_no_reply_url not set")
	}
	if config.Config.EmailDomain == "" {
		return common.InternalServerError("failed to send email: email_domain not set")
	}
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
