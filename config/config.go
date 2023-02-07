package config

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"github.com/caarlos0/env/v6"
	"github.com/creasty/defaults"
	"log"
	"net/url"
)

var Config struct {
	Mode                    string   `env:"MODE" envDefault:"dev"`
	DbUrl                   string   `env:"DB_URL,required"`
	KongUrl                 string   `env:"KONG_URL,required"`
	RedisUrl                string   `env:"REDIS_URL"`
	NotificationUrl         string   `env:"NOTIFICATION_URL"`
	EmailWhitelist          []string `env:"EMAIL_WHITELIST"`
	EmailServerNoReplyUrl   url.URL  `env:"EMAIL_SERVER_NO_REPLY_URL,required"`
	EmailDomain             string   `env:"EMAIL_DOMAIN,required"`
	EmailDev                string   `env:"EMAIL_DEV" envDefault:"dev@fduhole.com"`
	ShamirFeature           bool     `env:"SHAMIR_FEATURE" envDefault:"true"`
	VerificationCodeExpires int      `env:"VERIFICATION_CODE_EXPIRES" envDefault:"10"`
	SiteName                string   `env:"SITE_NAME" envDefault:"Open Tree Hole"`
}

var FileConfig struct {
	IdentifierSalt     string `env:"IDENTIFIER_SALT,file" envDefault:"/var/run/secrets/identifier_salt" default:""`
	ProvisionKey       string `env:"PROVISION_KEY,file" envDefault:"/var/run/secrets/provision_key" default:""`
	RegisterApikeySeed string `env:"REGISTER_APIKEY_SEED,file" envDefault:"/var/run/secrets/register_apikey_seed" default:""`
	KongToken          string `env:"KONG_TOKEN,file" envDefault:"/var/run/secrets/kong_token" default:""`
}

var DecryptedIdentifierSalt []byte
var RegisterApikeySecret string

func InitConfig() {
	var err error
	if err = env.Parse(&Config); err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", &Config)

	if err = env.Parse(&FileConfig); err != nil {
		if Config.Mode != "production" {
			log.Println(err)
			if err = defaults.Set(&FileConfig); err != nil {
				panic(err)
			}
		} else {
			panic(err)
		}
	}

	if FileConfig.IdentifierSalt == "" {
		DecryptedIdentifierSalt = []byte("123456")
	} else {
		DecryptedIdentifierSalt, err = base64.StdEncoding.DecodeString(FileConfig.IdentifierSalt)
		if err != nil {
			panic(err)
		}
	}

	RegisterApikeySecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(FileConfig.RegisterApikeySeed))
}
