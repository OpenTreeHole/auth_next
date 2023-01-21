package config

import (
	"encoding/base64"
	"fmt"
	"github.com/caarlos0/env/v6"
	"github.com/creasty/defaults"
	"log"
	"net/url"
	"time"
)

var Config struct {
	Mode                  string `env:"MODE" envDefault:"dev"`
	TZ                    string `env:"TZ" envDefault:"Asia/Shanghai"`
	TZLocation            *time.Location
	DbUrl                 string   `env:"DB_URL"`
	KongUrl               string   `env:"KONG_URL"`
	NotificationUrl       string   `env:"NOTIFICATION_URL"`
	EmailWhitelist        []string `env:"EMAIL_WHITELIST"`
	EmailServerNoReplyUrl url.URL  `env:"EMAIL_SERVER_NO_REPLY_URL"`
	EmailServerTestUrl    url.URL  `env:"EMAIL_SERVER_Test_URL"`
	EmailServerOpsUrl     url.URL  `env:"EMAIL_SERVER_Ops_URL"`
	EmailDomain           string   `env:"EMAIL_DOMAIN"`
	ShamirFeature         bool     `env:"SHAMIR_FEATURE" envDefault:"true"`

	VerificationCodeExpires int    `env:"VERIFICATION_CODE_EXPIRES" envDefault:"10"`
	SiteName                string `env:"SITE_NAME" envDefault:"Open Tree Hole"`
}

var FileConfig struct {
	RegisterApikeySeed      string `env:"REGISTER_APIKEY_SEED,file" envDefault:"/var/run/secret/register_apikey_seed" default:""`
	KongToken               string `env:"KONG_TOKEN,file" envDefault:"/var/run/secret/kong_token" default:""`
	IdentifierSalt          string `env:"IDENTIFIER_SALT,file" envDefault:"/var/run/secret/identifier_salt" default:""`
	DecryptedIdentifierSalt []byte
	ProvisionKey            string `env:"PROVISION_KEY,file" envDefault:"/var/run/secret/provision_key" default:""`
}

func init() {
	var err error
	if err := env.Parse(&Config); err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", &Config)

	// load TZ
	Config.TZLocation, err = time.LoadLocation(Config.TZ)
	if err != nil {
		panic(err)
	}

	if err := env.Parse(&FileConfig); err != nil {
		if Config.Mode != "production" {
			log.Println(err)
			if err := defaults.Set(&FileConfig); err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}

	if FileConfig.IdentifierSalt == "" {
		FileConfig.DecryptedIdentifierSalt = []byte("123456")
	} else {
		var err error
		FileConfig.DecryptedIdentifierSalt, err = base64.StdEncoding.DecodeString(FileConfig.IdentifierSalt)
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("%+v\n", &FileConfig)
}
