package utils

import (
	"auth_next/config"
	"testing"
	"time"
)

func TestSendEmail(t *testing.T) {
	config.InitConfig()

	if config.Config.EmailServerNoReplyUrl.Hostname() == "" {
		t.Fatal("no valid no-reply email server, please check your environment variables")
	}

	subject := "test email: " + time.Now().Format(time.RFC3339)
	content := subject
	err := SendEmail(subject, content, []string{"test@fduhole.com"})
	if err != nil {
		t.Fatal(err)
	}
}
