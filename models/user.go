package models

import (
	"database/sql"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/opentreehole/go-common"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
	"gorm.io/gorm"
)

type User struct {
	ID                   int            `json:"id" gorm:"primaryKey"`
	UserID               int            `json:"user_id" gorm:"-"`
	Nickname             string         `json:"nickname" gorm:"default:user;size:32"`
	Email                string         `json:"-" gorm:"-:all"`
	Identifier           sql.NullString `json:"-" gorm:"size:128;uniqueIndex:,length:10"`
	Password             string         `json:"-" gorm:"size:128"`
	IsAdmin              bool           `json:"is_admin" gorm:"default:false;index"`
	IsShamirAdmin        bool           `json:"is_shamir_admin" gorm:"default:false;index"`
	IsActive             bool           `json:"-" gorm:"default:true"`
	JoinedTime           time.Time      `json:"joined_time" gorm:"autoCreateTime"`
	LastLogin            time.Time      `json:"last_login" gorm:"autoUpdateTime"`
	UserJwtSecret        *UserJwtSecret `json:"-" gorm:"foreignKey:ID;references:ID"`
	HasAnsweredQuestions bool           `json:"has_answered_questions" gorm:"default:false"`
}

// AdminIDList and ShamirAdminIDList refresh every 1 minutes
var AdminIDList atomic.Value
var ShamirAdminIDList atomic.Value

func InitAdminList() {
	err := LoadAdminList()
	if err != nil {
		log.Fatal().Err(err).Msg("initial admin list failed")
	}
	go RefreshAdminList()
}

func InitShamirAdminList() {
	// init shamir admin list
	err := LoadShamirAdminList()
	if err != nil {
		log.Fatal().Err(err).Msg("initial shamir admin list failed")
	}
	go RefreshShamirAdminList()
}

func LoadAdminList() error {
	adminIDs := make([]int, 0, 10)
	err := DB.Model(&User{}).Where("is_admin = true").Pluck("id", &adminIDs).Error
	if err != nil {
		return err
	}
	AdminIDList.Store(adminIDs)
	return nil
}

func LoadShamirAdminList() error {
	// load shamir admin list
	shamirAdminIDs := make([]int, 0, 10)
	err := DB.Model(&User{}).Where("is_shamir_admin = true").Pluck("id", &shamirAdminIDs).Error
	if err != nil {
		return err
	}
	ShamirAdminIDList.Store(shamirAdminIDs)
	return nil
}

func RefreshAdminList() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		err := LoadAdminList()
		if err != nil {
			log.Err(err).Msg("refresh admin list failed")
		}
	}
}

func RefreshShamirAdminList() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		err := LoadShamirAdminList()
		if err != nil {
			log.Err(err).Msg("refresh admin list failed")
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
	_, ok := slices.BinarySearch(AdminIDList.Load().([]int), userID)
	return ok
}

func IsShamirAdmin(userID int) bool {
	_, ok := slices.BinarySearch(ShamirAdminIDList.Load().([]int), userID)
	return ok
}

func LoadUserFromDB(userID int) (*User, error) {
	var user User
	err := DB.Where("is_active = true").Take(&user, userID).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, common.NotFound("User Not Found")
		} else {
			return nil, err
		}
	} else {
		return &user, nil
	}
}

func GetUserByRefreshToken(c *fiber.Ctx) (string, *User, error) {
	// get id
	userID, ok := c.Locals("user_id").(int)
	if !ok {
		return "", nil, common.Unauthorized()
	}

	tokenString := c.Get("Authorization")
	if tokenString == "" { // token can be in either header or cookie
		tokenString = c.Cookies("refresh")
	}

	if strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = tokenString[7:] // extract "Bearer "
	}
	tokenString = strings.Trim(tokenString, " ")

	var payload Map
	err := common.ParseJWTToken(tokenString, &payload)
	if err != nil {
		return "", nil, err
	}

	if tokenType, ok := payload["type"]; !ok || tokenType != "refresh" {
		return "", nil, common.Unauthorized("refresh token invalid")
	}

	user, err := LoadUserFromDB(userID)

	return tokenString, user, err
}

func DeleteUserService(tx *gorm.DB, userID int, identifier string) error {
	return tx.Transaction(func(tx *gorm.DB) error {
		err := AddDeletedIdentifier(tx, userID, identifier)
		if err != nil {
			return err
		}

		return tx.Model(&User{ID: userID}).UpdateColumns(map[string]any{"is_active": false, "identifier": nil}).Error
	})
}
