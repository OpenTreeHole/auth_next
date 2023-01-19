package models

import (
	"auth_next/config"
	"auth_next/utils"
	"auth_next/utils/shamir"
	"errors"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"gorm.io/gorm"
)

type ShamirEmail struct {
	ID          int    `json:"id" gorm:"primaryKey"`
	UserID      int    `json:"user_id"`
	EncryptedBy string `json:"encrypted_by"`
	Key         string `json:"key"`
}

type ShamirPublicKey struct {
	ID               int             `json:"-" gorm:"primaryKey"`
	IdentityName     string          `json:"identity_name"`
	ArmoredPublicKey string          `json:"-"`
	PublicKey        *crypto.KeyRing `json:"-" gorm:"-"`
}

var ShamirPublicKeys []ShamirPublicKey

func LoadShamirPublicKey() error {
	if !config.Config.ShamirFeature {
		return nil
	}

	ShamirPublicKeys = make([]ShamirPublicKey, 0)
	result := DB.Find(&ShamirPublicKeys)
	if result.Error != nil {
		return result.Error
	}

	// check if stored public keys in the database
	if len(ShamirPublicKeys) == 0 {
		return errors.New("shamir public key not found, please check your database")
	}

	// check public key validity
	for i := range ShamirPublicKeys {
		identityName := ShamirPublicKeys[i].IdentityName

		// parse key
		key, err := crypto.NewKeyFromArmored(ShamirPublicKeys[i].ArmoredPublicKey)
		if err != nil {
			return fmt.Errorf("%v; IdentityName: %v\n", err.Error(), identityName)
		}

		entity := key.GetEntity()
		if entity == nil || len(entity.Identities) == 0 {
			return fmt.Errorf("no identity found in this public key; IdentityName: %v\n", identityName)
		}

		// get all identity name in this public key
		identityNameList := make([]string, 0, len(entity.Identities))
		for name := range entity.Identities {
			identityNameList = append(identityNameList, name)
		}

		// check if public key contains identity name stored in database
		if !utils.InUnorderedSlice(identityNameList, identityName) {
			return fmt.Errorf("identity name not in public key, please check your database; IdentityName: %v\n", identityName)
		}

		// transform public key to key ring
		ShamirPublicKeys[i].PublicKey, err = crypto.NewKeyRing(key)
		if err != nil {
			return fmt.Errorf("cannot generate keyring from key; IdentityName: %v\n", identityName)
		}
	}

	// all check success
	return nil
}

func CreateShamirEmails(tx *gorm.DB, userID int, shares []shamir.Share) error {
	if len(shares) != len(ShamirPublicKeys) {
		return errors.New("shares len != shamir public key len, please check your public key or share settings")
	}
	shamirEmails := make([]ShamirEmail, 0, len(shares))

	// encrypt with pgp public keys
	for i := range shares {
		shareText := shares[i].ToString()
		sharePlanMessage := crypto.NewPlainMessageFromString(shareText)
		pgpMessage, err := ShamirPublicKeys[i].PublicKey.Encrypt(sharePlanMessage, nil)
		if err != nil {
			return err
		}
		armoredPGPMessage, err := pgpMessage.GetArmored()
		if err != nil {
			return err
		}
		shamirEmails = append(shamirEmails, ShamirEmail{
			UserID:      userID,
			EncryptedBy: ShamirPublicKeys[i].IdentityName,
			Key:         armoredPGPMessage,
		})
	}

	// save into database
	return tx.Create(shamirEmails).Error
}
