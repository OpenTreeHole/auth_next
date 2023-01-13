package models

import "time"

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
