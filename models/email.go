package models

import (
	"encoding/hex"
	"golang.org/x/crypto/sha3"
)

type EmailList struct {
	Hash string `json:"hash" gorm:"primaryKey;size:128"`
}

func sha3SumEmail(email string) string {
	sum512ByteArray := sha3.Sum512([]byte(email))
	sum512ByteSlice := sum512ByteArray[0:]
	return hex.EncodeToString(sum512ByteSlice)
}

func hasEmail(model any, email string) bool {
	var count int64
	result := DB.Model(model).Where("hash = ?", sha3SumEmail(email)).Count(&count)
	return result.Error == nil && count > 0
}

func addEmail(model any, email string) error {
	return DB.Model(model).Create(Map{"hash": sha3SumEmail(email)}).Error
}

func deleteEmail(model any, email string) error {
	return DB.Model(model).Delete(Map{"hash": sha3SumEmail(email)}).Error
}

type RegisteredEmail EmailList

type DeletedEmail EmailList

func HasRegisteredEmail(email string) bool {
	return hasEmail(RegisteredEmail{}, email)
}

func HasDeletedEmail(email string) bool {
	return hasEmail(DeletedEmail{}, email)
}

func AddRegisteredEmail(email string) error {
	return addEmail(RegisteredEmail{}, email)
}

func AddDeletedEmail(email string) error {
	return addEmail(DeletedEmail{}, email)
}

func DeleteDeletedEmail(email string) error {
	return deleteEmail(DeletedEmail{}, email)
}
