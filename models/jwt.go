package models

import (
	"auth_next/config"
	"auth_next/utils/kong"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/thanhpk/randstr"
	"gorm.io/gorm"
	"time"
)

type UserJwtSecret struct {
	ID     int    `json:"id" gorm:"primaryKey"`
	Secret string `json:"secret" gorm:"size:256"`
}

type UserClaims struct {
	jwt.RegisteredClaims
	ID         int       `json:"id"`
	UserID     int       `json:"user_id"`
	UID        int       `json:"uid"`
	Type       string    `json:"type"`
	Nickname   string    `json:"nickname"`
	JoinedTime time.Time `json:"joined_time"`
	IsAdmin    bool      `json:"is_admin"`
}

const (
	JWTTypeAccess  = "access"
	JWTTypeRefresh = "refresh"
)

func (user *User) CreateJWTToken() (accessToken, refreshToken string, err error) {
	// get jwt key and secret
	var key, secret string

	if config.Config.Standalone {
		// no gateway, store jwt secret in database
		var userJwtSecret UserJwtSecret
		err = DB.Take(&userJwtSecret, user.ID).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				userJwtSecret = UserJwtSecret{
					ID:     user.ID,
					Secret: randstr.Base62(32),
				}
				err = DB.Create(&userJwtSecret).Error
				if err != nil {
					return "", "", err
				}
			} else {
				return "", "", err
			}
		}

		key = fmt.Sprintf("user_%d", user.ID)
		secret = userJwtSecret.Secret
	} else {
		key, secret, err = kong.GetJwtSecret(user.ID)
		if err != nil {
			return "", "", err
		}
	}

	// create JWT token
	claim := UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    key,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)), // // 30 minutes
		},
		ID:         user.ID,
		UserID:     user.UserID,
		UID:        user.UserID,
		Nickname:   user.Nickname,
		JoinedTime: user.JoinedTime,
		IsAdmin:    user.IsAdmin,
		Type:       JWTTypeAccess,
	}

	// access payload
	accessToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claim).SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}

	// refresh payload
	claim.Type = JWTTypeRefresh
	claim.ExpiresAt = jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)) // 30 days
	refreshToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, claim).SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}

	return
}
