package models

import (
	"auth_next/config"
	"auth_next/utils"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/exp/slices"
	"strconv"
	"time"
)

type User struct {
	ID         int       `json:"id" gorm:"primaryKey"`
	Nickname   string    `json:"nickname" gorm:"default:user;size:32"`
	Identifier string    `json:"-" gorm:"size:128;unique"`
	Password   string    `json:"-" gorm:"size:128"`
	IsAdmin    bool      `json:"is_admin" gorm:"default:false;index"`
	IsActive   bool      `json:"-" gorm:"default:true;index"`
	JoinedTime time.Time `json:"joined_time"`
	LastLogin  time.Time `json:"last_login"`
}

// AdminIDList refresh every 10 minutes
var AdminIDList []int

func GetAdminList() error {
	return DB.Table("user").Select("id").Order("id asc").Find(&AdminIDList, "is_admin = true").Error
}

func IsAdmin(userID int) bool {
	if AdminIDList == nil {
		return false
	}
	_, ok := slices.BinarySearch(AdminIDList, userID)
	return ok
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
