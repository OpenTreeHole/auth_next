package auth

import (
	"auth_next/config"
	"context"
	"crypto/rand"
	"fmt"
	"github.com/eko/gocache/lib/v4/cache"
	gocacheStore "github.com/eko/gocache/store/go_cache/v4"
	redisStore "github.com/eko/gocache/store/redis/v4"
	gocache "github.com/patrickmn/go-cache"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
	"log"
	"math/big"
	"time"
)

var verificationCodeCache *cache.Cache[string]

func InitVerificationCodeCache() {
	if config.Config.RedisUrl != "" {
		verificationCodeCache = cache.New[string](
			redisStore.NewRedis(
				redis.NewClient(
					&redis.Options{
						Addr: config.Config.RedisUrl,
					},
				),
			),
		)
		log.Println("verification code cache: redis")
	} else {
		verificationCodeCache = cache.New[string](
			gocacheStore.NewGoCache(
				gocache.New(
					time.Duration(config.Config.VerificationCodeExpires)*time.Minute,
					20*time.Minute),
			),
		)
		log.Println("verification code cache: gocache")
	}
}

// SetVerificationCode 缓存中设置验证码，key = {scope}-{many_hashes(email)}
func SetVerificationCode(email, scope string) (string, error) {
	codeInt, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	code := fmt.Sprintf("%06d", codeInt.Uint64())

	return code, verificationCodeCache.Set(
		context.Background(),
		fmt.Sprintf("%v-%v", scope, MakeIdentifier(email)),
		code,
	)
}

// CheckVerificationCode 检查验证码
func CheckVerificationCode(email, scope, code string) bool {
	storedCode, err := verificationCodeCache.Get(
		context.Background(),
		fmt.Sprintf("%v-%v", scope, MakeIdentifier(email)),
	)
	return err == nil && storedCode == code
}

func DeleteVerificationCode(email, scope string) error {
	return verificationCodeCache.Delete(
		context.Background(),
		fmt.Sprintf("%v-%v", scope, MakeIdentifier(email)),
	)
}

func CheckApikey(key string) bool {
	ok, err := totp.ValidateCustom(
		key,
		config.RegisterApikeySecret,
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    5,
			Skew:      1,
			Digits:    16,
			Algorithm: otp.AlgorithmSHA256,
		})
	if err != nil {
		log.Printf("verify api key error: %s\n", err)
		return false
	}
	return ok
}
