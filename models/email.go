package models

import (
	"encoding/hex"
	"golang.org/x/crypto/sha3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type EmailList struct {
	Hash string `json:"hash" gorm:"primaryKey;size:128;uniqueIndex:idx_email_hash,length:10"`
}

func Sha3SumEmail(email string) string {
	sum512ByteArray := sha3.Sum512([]byte(email))
	return hex.EncodeToString(sum512ByteArray[:])
}

func hasEmail(tx *gorm.DB, model any, email string) (bool, error) {
	var count int64
	result := tx.Model(model).Where("hash = ?", Sha3SumEmail(email)).Count(&count)
	return count > 0, result.Error
}

func addEmail(tx *gorm.DB, model any, email string) error {
	return tx.Model(model).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(Map{"hash": Sha3SumEmail(email)}).Error
}

func deleteEmail(tx *gorm.DB, model any, email string) error {
	return tx.Where("hash = ?", Sha3SumEmail(email)).Delete(model).Error
}

type RegisteredEmail EmailList

type DeletedEmail EmailList

func HasRegisteredEmail(tx *gorm.DB, email string) (bool, error) {
	return hasEmail(tx, RegisteredEmail{}, email)
}

func HasDeletedEmail(tx *gorm.DB, email string) (bool, error) {
	return hasEmail(tx, DeletedEmail{}, email)
}

func AddRegisteredEmail(tx *gorm.DB, email string) error {
	return addEmail(tx, RegisteredEmail{}, email)
}

func AddDeletedEmail(tx *gorm.DB, email string) error {
	return addEmail(tx, DeletedEmail{}, email)
}

func DeleteDeletedEmail(tx *gorm.DB, email string) error {
	return deleteEmail(tx, DeletedEmail{}, email)
}
