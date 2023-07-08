package config

import (
	"encoding/base32"
	"encoding/base64"
	"github.com/caarlos0/env/v9"
	"github.com/rs/zerolog/log"
	"net/url"
)

const (
	DefaultShamirKeyCount = 7
)

var Config struct {
	Mode                    string   `env:"MODE" envDefault:"dev"`
	DbUrl                   string   `env:"DB_URL"`
	KongUrl                 string   `env:"KONG_URL"`
	RedisUrl                string   `env:"REDIS_URL"`
	NotificationUrl         string   `env:"NOTIFICATION_URL"`
	EmailWhitelist          []string `env:"EMAIL_WHITELIST"`
	EmailServerNoReplyUrl   url.URL  `env:"EMAIL_SERVER_NO_REPLY_URL,required"`
	EmailDomain             string   `env:"EMAIL_DOMAIN,required"`
	EmailDev                string   `env:"EMAIL_DEV" envDefault:"dev@fduhole.com"`
	ShamirFeature           bool     `env:"SHAMIR_FEATURE" envDefault:"true"`
	Standalone              bool     `env:"STANDALONE" envDefault:"false"`
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
	err = env.Parse(&Config)
	if err != nil {
		log.Fatal().Err(err)
	}
	log.Info().Any("config", Config).Send()

	initFileConfig()

	if FileConfig.IdentifierSalt == "" {
		if Config.Mode == "production" {
			log.Fatal().Msg("identifier salt not set")
		} else {
			DecryptedIdentifierSalt = []byte("123456")
		}
	} else {
		DecryptedIdentifierSalt, err = base64.StdEncoding.DecodeString(FileConfig.IdentifierSalt)
		if err != nil {
			log.Fatal().Err(err).Msg("decode identifier salt error")
		}
	}

	if FileConfig.RegisterApikeySeed == "" && Config.Mode == "production" {
		log.Fatal().Msg("register apikey seed not set")
	}
	RegisterApikeySecret = base32.StdEncoding.EncodeToString([]byte(FileConfig.RegisterApikeySeed))
}

func initFileConfig() {
	err := env.Parse(&FileConfig)
	if err != nil {
		if e, ok := err.(*env.AggregateError); ok {
			for _, innerErr := range e.Errors {
				switch innerErr.(type) {
				case env.LoadFileContentError:
					continue
				default:
					log.Fatal().Err(err).Msg("init file config error")
				}
			}
		}
	}
}
