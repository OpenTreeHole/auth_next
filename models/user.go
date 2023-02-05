package models

import (
	"auth_next/config"
	"auth_next/utils"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/exp/slices"
	"gorm.io/gorm"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type User struct {
	ID         int       `json:"id" gorm:"primaryKey"`
	UserID     int       `json:"user_id" gorm:"-"`
	Nickname   string    `json:"nickname" gorm:"default:user;size:32"`
	Identifier string    `json:"-" gorm:"size:128;uniqueIndex:idx_user_identifier,length:10"`
	Password   string    `json:"-" gorm:"size:128"`
	IsAdmin    bool      `json:"is_admin" gorm:"default:false;index"`
	IsActive   bool      `json:"-" gorm:"default:true"`
	JoinedTime time.Time `json:"joined_time" gorm:"autoCreateTime"`
	LastLogin  time.Time `json:"last_login" gorm:"autoUpdateTime"`
}

// AdminIDList refresh every 1 minutes
var AdminIDList atomic.Value

func GetAdminList() error {
	adminIDs := make([]int, 0, 10)
	err := DB.Table("user").Select("id").Order("id asc").Find(&adminIDs, "is_admin = true").Error
	if err != nil {
		return err
	}
	AdminIDList.Store(adminIDs)
	return nil
}

func RefreshAdminList() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		err := GetAdminList()
		if err != nil {
			log.Println(err)
		}
	}
}

func (user *User) AfterCreate(_ *gorm.DB) error {
	user.UserID = user.ID
	return nil
}

func (user *User) AfterFind(_ *gorm.DB) error {
	user.UserID = user.ID
	return nil
}

func IsAdmin(userID int) bool {
	if config.Config.Mode == "dev" {
		return true
	}
	_, ok := slices.BinarySearch(AdminIDList.Load().([]int), userID)
	return ok
}

func LoadUserFromDB(userID int) (*User, error) {
	var user User
	err := DB.Where("is_active = true").Take(&user, userID).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, utils.NotFound("User Not Found")
		} else {
			return nil, err
		}
	} else {
		return &user, nil
	}
}

func GetUserID(c *fiber.Ctx) (int, error) {
	if config.Config.Mode == "dev" || config.Config.Mode == "test" {
		return 1, nil
	}

	id, err := strconv.Atoi(c.Get("X-Consumer-Username"))
	if err != nil {
		return 0, utils.Unauthorized("Unauthorized")
	}

	return id, nil
}

// parseJWT extracts and parse token
func parseJWT(token string) (Map, error) {
	if len(token) < 7 {
		return nil, errors.New("bearer token required")
	}

	payloads := strings.SplitN(token[7:], ".", 3) // extract "Bearer "
	if len(payloads) < 3 {
		return nil, errors.New("jwt token required")
	}

	// jwt encoding ignores padding, so RawStdEncoding should be used instead of StdEncoding
	payloadBytes, err := base64.RawStdEncoding.DecodeString(payloads[1]) // the middle one is payload
	if err != nil {
		return nil, err
	}

	var value Map
	err = json.Unmarshal(payloadBytes, &value)
	return value, err
}

func GetUserByRefreshToken(c *fiber.Ctx) (*User, error) {
	// get id
	userID, err := GetUserID(c)
	if err != nil {
		return nil, err
	}

	tokenString := c.Get("Authorization")
	if tokenString == "" { // token can be in either header or cookie
		tokenString = c.Cookies("refresh")
	}

	payload, err := parseJWT(tokenString)
	if err != nil {
		return nil, err
	}

	if tokenType, ok := payload["type"]; !ok || tokenType != "refresh" {
		return nil, utils.Unauthorized("refresh token invalid")
	}

	return LoadUserFromDB(userID)
}
