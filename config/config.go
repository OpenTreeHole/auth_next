package config

import (
	"fmt"
	"github.com/caarlos0/env/v6"
	"log"
)

var Config struct {
	Mode            string   `env:"MODE" envDefault:"dev"`
	DbUrl           string   `env:"DB_URL"`
	KongUrl         string   `env:"KONG_URL"`
	NotificationUrl string   `env:"NOTIFICATION_URL"`
	EmailWhitelist  []string `env:"EMAIL_WHITELIST"`
	EmailHost       string   `env:"EMAIL_HOST"`
	EmailUsername   string   `env:"EMAIL_USERNAME"`
	EmailPassword   string   `env:"EMAIL_PASSWORD"`
	EmailPort       int      `env:"EMAIL_PORT" envDefault:"465"`
	EmailUseTLS     bool     `env:"EMAIL_USE_TLS" envDefault:"true"`
	ShamirFeature   bool     `env:"SHAMIR_FEATURE" envDefault:"true"`
	// send email to dev team when errors happen or tasks finish
	EmailDev string `env:"EMAIL_DEV" envDefault:"dev@fduhole.com"`

	// get from docker secret
	//RegisterApikeySeed string `env:"REGISTER_APIKEY_SEED,file" envDefault:"/var/run/secret/register_apikey_seed"`
	//KongToken          string `env:"KONG_TOKEN,file" envDefault:"/var/run/secret/kong_token"`
	//IdentifierSalt     string `env:"IDENTIFIER_SALT,file" envDefault:"/var/run/secret/identifier_salt"`
	//ProvisionKey       string `env:"PROVISION_KEY,file" envDefault:"/var/run/secret/provision_key"`
}

func init() {
	if err := env.Parse(&Config); err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("%+v\n", &Config)
}
