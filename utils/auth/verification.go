package auth

import (
	"auth_next/config"
	"context"
	"crypto/rand"
	"fmt"
	"github.com/eko/gocache/lib/v4/cache"
	gocache_store "github.com/eko/gocache/store/go_cache/v4"
	gocache "github.com/patrickmn/go-cache"
	"math/big"
	"time"
)

var verificationCodeCache *cache.Cache[string]

func init() {
	gocacheClient := gocache.New(time.Duration(config.Config.VerificationCodeExpires)*time.Minute, 20*time.Minute)
	gocacheStore := gocache_store.NewGoCache(gocacheClient)
	verificationCodeCache = cache.New[string](gocacheStore)
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
func CheckVerificationCode(email, scope, code string) (bool, error) {
	storedCode, err := verificationCodeCache.Get(
		context.Background(),
		fmt.Sprintf("%v-%v", scope, MakeIdentifier(email)),
	)
	if err != nil {
		return false, err
	}
	return storedCode == code, nil
}

func DeleteVerificationCode(email, scope string) error {
	return verificationCodeCache.Delete(
		context.Background(),
		fmt.Sprintf("%v-%v", scope, MakeIdentifier(email)),
	)
}
