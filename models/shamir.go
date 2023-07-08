package models

import (
	"auth_next/config"
	"auth_next/utils/shamir"
	"errors"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"os"
)

type ShamirEmail struct {
	ID          int    `json:"id" gorm:"primaryKey"`
	UserID      int    `json:"user_id" gorm:"uniqueIndex:idx_key_uid,priority:2"`
	EncryptedBy string `json:"encrypted_by" gorm:"uniqueIndex:idx_key_uid,priority:1,length:5"`
	Key         string `json:"key"`
}

type ShamirPublicKey struct {
	ID               int             `json:"id" gorm:"primaryKey"`
	IdentityName     string          `json:"identity_name" gorm:"not null"`
	ArmoredPublicKey string          `json:"armored_public_key" gorm:"not null"`
	PublicKey        *crypto.KeyRing `json:"-" gorm:"-"`
}

var ShamirPublicKeys []ShamirPublicKey

// InitShamirPublicKey initialize shamir public key.
// if found in database, load from database,
// else generate from default keys
func InitShamirPublicKey() {
	if !config.Config.ShamirFeature {
		return
	}

	ShamirPublicKeys = make([]ShamirPublicKey, 0)
	err := DB.Find(&ShamirPublicKeys).Error
	if err != nil {
		log.Fatal().Err(err).Msg("load shamir public key failed")
	}

	// check if stored public keys in the database
	if len(ShamirPublicKeys) == 0 {
		// no public key found, generate using default keys
		log.Warn().Msg("no public key found in database, using default keys")

		// load keys from data dir
		for i := 1; i <= config.DefaultShamirKeyCount; i++ {
			filename := fmt.Sprintf("data/%d-public.key", i)

			// read public key
			armoredPublicKeyBytes, err := os.ReadFile(filename)
			if err != nil {
				log.Fatal().Err(err).Msg("read default public key failed")
			}
			armoredPublicKey := string(armoredPublicKeyBytes)

			// parse key
			key, err := crypto.NewKeyFromArmored(armoredPublicKey)
			if err != nil {
				log.Fatal().Err(err).Msg("parse default public key failed")
			}

			// transform public key to key ring
			keyRing, err := crypto.NewKeyRing(key)
			if err != nil {
				log.Fatal().Err(err).Msg("cannot generate keyring from key")
			}

			// append to public key list
			ShamirPublicKeys = append(ShamirPublicKeys, ShamirPublicKey{
				ID:               i,
				IdentityName:     key.GetEntity().PrimaryIdentity().Name,
				ArmoredPublicKey: armoredPublicKey,
				PublicKey:        keyRing,
			})
		}

		// save public key list to database
		err := DB.Save(&ShamirPublicKeys).Error
		if err != nil {
			log.Fatal().Err(err).Msg("save default public key failed")
		}
	} else {
		// check public key validity
		for i := range ShamirPublicKeys {
			identityName := ShamirPublicKeys[i].IdentityName

			// parse key
			key, err := crypto.NewKeyFromArmored(ShamirPublicKeys[i].ArmoredPublicKey)
			if err != nil {
				log.Fatal().Err(err).Str("identity_name", identityName).Msg("parse key failed")
			}

			// check identity name
			if key.GetEntity().PrimaryIdentity().Name != identityName {
				log.Fatal().
					Str("identity_name", identityName).
					Msg("identity name not in public key, please check your database")
			}

			// transform public key to key ring
			ShamirPublicKeys[i].PublicKey, err = crypto.NewKeyRing(key)
			if err != nil {
				log.Fatal().
					Str("identity_name", identityName).
					Msg("cannot generate keyring from key")
			}
		}
	}
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
