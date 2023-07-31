package models

import (
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"auth_next/utils/auth"
)

type DeleteIdentifier struct {
	UserID     int    `json:"user_id" gorm:"primaryKey"`
	Identifier string `json:"identifier" gorm:"size:128;uniqueIndex:,length:10"`
}

func HasRegisteredEmail(tx *gorm.DB, email string) (bool, error) {
	var exists bool
	err := tx.Raw("SELECT EXISTS (SELECT 1 FROM user WHERE identifier = ?)", auth.MakeIdentifier(email)).Scan(&exists).Error
	return exists, err
}

func HasDeletedEmail(tx *gorm.DB, email string) (bool, error) {
	var exists bool
	err := tx.Raw("SELECT EXISTS (SELECT 1 FROM delete_identifier WHERE identifier = ?)", auth.MakeIdentifier(email)).Scan(&exists).Error
	return exists, err
}

func AddDeletedIdentifier(tx *gorm.DB, userID int, identifier string) error {
	deleteIdentifier := DeleteIdentifier{UserID: userID, Identifier: identifier}
	return tx.
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(&deleteIdentifier).Error
}
