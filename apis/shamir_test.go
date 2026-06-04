package apis

import (
	"fmt"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"auth_next/config"
	"auth_next/models"
	"auth_next/utils/shamir"
)

func TestDecryptUserEmailWithThresholdSkipsBadShare(t *testing.T) {
	const email = "test@example.com"

	shares, err := shamir.Encrypt(email, 5, 4)
	if err != nil {
		t.Fatal(err)
	}

	shares[2] = shamir.Share{
		X: big.NewInt(12345),
		Y: big.NewInt(67890),
	}

	response, ok := decryptUserEmailWithThreshold(1, shares, []string{"a", "b", "c", "d", "e"}, 4)
	if !ok {
		t.Fatal("expected decrypt to succeed")
	}
	if response.UserEmail != email {
		t.Fatalf("expected email %q, got %q", email, response.UserEmail)
	}
	for _, identityName := range response.IdentityNames {
		if identityName == "c" {
			t.Fatal("expected successful identity names to skip bad share")
		}
	}
}

func TestDecryptUserEmailWithThreeOfFive(t *testing.T) {
	const email = "test@example.com"

	shares, err := shamir.Encrypt(email, 5, 3)
	if err != nil {
		t.Fatal(err)
	}

	response, ok := decryptUserEmailWithThreshold(1, shares[:3], []string{"a", "b", "c"}, 3)
	if !ok {
		t.Fatal("expected decrypt to succeed")
	}
	if response.UserEmail != email {
		t.Fatalf("expected email %q, got %q", email, response.UserEmail)
	}
	if len(response.IdentityNames) != 3 {
		t.Fatalf("expected 3 identity names, got %d", len(response.IdentityNames))
	}
}

func TestUpdateShamirPersistsFiveKeyLocalSQLite(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth_next_shamir_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{SingularTable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	if err := db.AutoMigrate(models.ShamirEmail{}, models.ShamirPublicKey{}); err != nil {
		t.Fatal(err)
	}

	oldDB := models.DB
	oldPublicKeys := models.ShamirPublicKeys
	oldShamirFeature := config.Config.ShamirFeature
	t.Cleanup(func() {
		models.DB = oldDB
		models.ShamirPublicKeys = oldPublicKeys
		config.Config.ShamirFeature = oldShamirFeature
		InitShamirStatus()
	})

	models.DB = db
	config.Config.ShamirFeature = true

	publicKeys, privateKeyRings := generateTestKeySet(t, 7)
	models.ShamirPublicKeys = publicKeys
	if err := db.Create(&publicKeys).Error; err != nil {
		t.Fatal(err)
	}

	const (
		userID = 1001
		email  = "localdb@example.com"
	)
	if err := models.CreateShamirEmails(db, userID, email); err != nil {
		t.Fatal(err)
	}

	var oldEmailCount int64
	if err := db.Model(&models.ShamirEmail{}).Where("user_id = ?", userID).Count(&oldEmailCount).Error; err != nil {
		t.Fatal(err)
	}
	if oldEmailCount != 7 {
		t.Fatalf("expected 7 old shamir email rows, got %d", oldEmailCount)
	}

	oldShares, err := shamir.Encrypt(email, 7, 4)
	if err != nil {
		t.Fatal(err)
	}

	InitShamirStatus()
	GlobalUploadShamirStatus.UploadedSharesIdentityNames = []string{"key-1", "key-2", "key-3", "key-4"}
	GlobalUploadShamirStatus.UploadedShares[userID] = oldShares[:4]
	GlobalUploadShamirStatus.NewPublicKeys = publicKeys[:5]
	GlobalUploadShamirStatus.ShamirUpdateReady = true

	updateShamir()

	if GlobalUploadShamirStatus.FailMessage != "" {
		t.Fatalf("updateShamir failed: %s", GlobalUploadShamirStatus.FailMessage)
	}

	var persistedKeyCount int64
	if err := db.Model(&models.ShamirPublicKey{}).Count(&persistedKeyCount).Error; err != nil {
		t.Fatal(err)
	}
	if persistedKeyCount != 5 {
		t.Fatalf("expected 5 persisted public keys, got %d", persistedKeyCount)
	}

	var newEmailCount int64
	if err := db.Model(&models.ShamirEmail{}).Where("user_id = ?", userID).Count(&newEmailCount).Error; err != nil {
		t.Fatal(err)
	}
	if newEmailCount != 5 {
		t.Fatalf("expected successful user to keep only 5 new shamir email rows, got %d", newEmailCount)
	}

	currentIdentityNames := make([]string, 0, 5)
	for _, publicKey := range publicKeys[:5] {
		currentIdentityNames = append(currentIdentityNames, publicKey.IdentityName)
	}
	var currentEmailCount int64
	if err := db.Model(&models.ShamirEmail{}).
		Where("user_id = ? AND encrypted_by IN ?", userID, currentIdentityNames).
		Count(&currentEmailCount).Error; err != nil {
		t.Fatal(err)
	}
	if currentEmailCount != 5 {
		t.Fatalf("expected 5 current shamir email rows, got %d", currentEmailCount)
	}

	newShares := make(shamir.Shares, 0, 3)
	for i := 0; i < 3; i++ {
		var shamirEmail models.ShamirEmail
		if err := db.Where("user_id = ? AND encrypted_by = ?", userID, publicKeys[i].IdentityName).
			Take(&shamirEmail).Error; err != nil {
			t.Fatal(err)
		}

		share, err := decryptTestShare(privateKeyRings[i], shamirEmail.Key)
		if err != nil {
			t.Fatal(err)
		}
		newShares = append(newShares, share)
	}
	if decryptedEmail := shamir.Decrypt(newShares); decryptedEmail != email {
		t.Fatalf("expected decrypted updated email %q, got %q", email, decryptedEmail)
	}

	models.ShamirPublicKeys = nil
	models.InitShamirPublicKey()
	if got := len(models.ShamirPublicKeys); got != 5 {
		t.Fatalf("expected reload to auto-detect 5 public keys, got %d", got)
	}
	if got := config.ShamirThreshold(len(models.ShamirPublicKeys)); got != 3 {
		t.Fatalf("expected 3-of-5 threshold after reload, got %d", got)
	}
}

func TestUpdateShamirInvalidShareDoesNotPanic(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth_next_shamir_invalid_share_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{SingularTable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	if err := db.AutoMigrate(models.ShamirEmail{}, models.ShamirPublicKey{}); err != nil {
		t.Fatal(err)
	}

	oldDB := models.DB
	oldPublicKeys := models.ShamirPublicKeys
	oldShamirFeature := config.Config.ShamirFeature
	t.Cleanup(func() {
		models.DB = oldDB
		models.ShamirPublicKeys = oldPublicKeys
		config.Config.ShamirFeature = oldShamirFeature
		InitShamirStatus()
	})

	models.DB = db
	config.Config.ShamirFeature = true

	publicKeys, _ := generateTestKeySet(t, 5)
	models.ShamirPublicKeys = publicKeys
	if err := db.Create(&publicKeys).Error; err != nil {
		t.Fatal(err)
	}

	const email = "invalid-share@example.com"
	for userID := 1; userID <= 20; userID++ {
		if err := models.CreateShamirEmails(db, userID, email); err != nil {
			t.Fatal(err)
		}
	}

	validShares, err := shamir.Encrypt(email, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	invalidShares := append(shamir.Shares(nil), validShares[:3]...)
	invalidShares[0] = shamir.Share{
		X: big.NewInt(12345),
		Y: big.NewInt(67890),
	}

	InitShamirStatus()
	GlobalUploadShamirStatus.UploadedSharesIdentityNames = []string{"key-1", "key-2", "key-3"}
	GlobalUploadShamirStatus.UploadedShares[1] = invalidShares
	for userID := 2; userID <= 20; userID++ {
		GlobalUploadShamirStatus.UploadedShares[userID] = validShares[:3]
	}
	GlobalUploadShamirStatus.NewPublicKeys = publicKeys
	GlobalUploadShamirStatus.ShamirUpdateReady = true

	updateShamir()

	if GlobalUploadShamirStatus.FailMessage == "" {
		t.Fatal("expected updateShamir to record invalid share failure")
	}

	var emailCount int64
	if err := db.Model(&models.ShamirEmail{}).Count(&emailCount).Error; err != nil {
		t.Fatal(err)
	}
	if emailCount != 100 {
		t.Fatalf("expected old shamir email rows to remain, got %d", emailCount)
	}
}

func TestUpdateShamirPartialUpdateAllowedAtNinetyNinePercent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "auth_next_shamir_partial_update_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{SingularTable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	if err := db.AutoMigrate(models.ShamirEmail{}, models.ShamirPublicKey{}); err != nil {
		t.Fatal(err)
	}

	oldDB := models.DB
	oldPublicKeys := models.ShamirPublicKeys
	oldShamirFeature := config.Config.ShamirFeature
	t.Cleanup(func() {
		models.DB = oldDB
		models.ShamirPublicKeys = oldPublicKeys
		config.Config.ShamirFeature = oldShamirFeature
		InitShamirStatus()
	})

	models.DB = db
	config.Config.ShamirFeature = true

	publicKeys, _ := generateTestKeySet(t, 5)
	models.ShamirPublicKeys = publicKeys
	if err := db.Create(&publicKeys).Error; err != nil {
		t.Fatal(err)
	}

	const email = "partial-update@example.com"
	for userID := 1; userID <= 100; userID++ {
		if err := models.CreateShamirEmails(db, userID, email); err != nil {
			t.Fatal(err)
		}
	}

	validShares, err := shamir.Encrypt(email, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	invalidShares := append(shamir.Shares(nil), validShares[:3]...)
	invalidShares[0] = shamir.Share{
		X: big.NewInt(12345),
		Y: big.NewInt(67890),
	}

	InitShamirStatus()
	GlobalUploadShamirStatus.UploadedSharesIdentityNames = []string{"key-1", "key-2", "key-3"}
	GlobalUploadShamirStatus.UploadedShares[1] = invalidShares
	for userID := 2; userID <= 100; userID++ {
		GlobalUploadShamirStatus.UploadedShares[userID] = validShares[:3]
	}
	GlobalUploadShamirStatus.NewPublicKeys = publicKeys[:3]
	GlobalUploadShamirStatus.ShamirUpdateReady = true

	updateShamir()

	if GlobalUploadShamirStatus.FailMessage != "" {
		t.Fatalf("expected partial update to succeed, got fail message: %s", GlobalUploadShamirStatus.FailMessage)
	}
	if GlobalUploadShamirStatus.WarningMessage == "" {
		t.Fatal("expected skipped user warning")
	}

	var persistedKeyCount int64
	if err := db.Model(&models.ShamirPublicKey{}).Count(&persistedKeyCount).Error; err != nil {
		t.Fatal(err)
	}
	if persistedKeyCount != 3 {
		t.Fatalf("expected 3 persisted public keys after partial update, got %d", persistedKeyCount)
	}

	var emailCount int64
	if err := db.Model(&models.ShamirEmail{}).Count(&emailCount).Error; err != nil {
		t.Fatal(err)
	}
	if emailCount != 302 {
		t.Fatalf("expected skipped user to keep old rows and successful users to be replaced, got %d shamir email rows", emailCount)
	}

	var skippedUserEmailCount int64
	if err := db.Model(&models.ShamirEmail{}).Where("user_id = ?", 1).Count(&skippedUserEmailCount).Error; err != nil {
		t.Fatal(err)
	}
	if skippedUserEmailCount != 5 {
		t.Fatalf("expected skipped user to keep 5 old shamir email rows, got %d", skippedUserEmailCount)
	}

	var successfulUserEmailCount int64
	if err := db.Model(&models.ShamirEmail{}).Where("user_id = ?", 2).Count(&successfulUserEmailCount).Error; err != nil {
		t.Fatal(err)
	}
	if successfulUserEmailCount != 3 {
		t.Fatalf("expected successful user to keep only 3 new shamir email rows, got %d", successfulUserEmailCount)
	}
}

func generateTestKeySet(t *testing.T, n int) ([]models.ShamirPublicKey, []*crypto.KeyRing) {
	t.Helper()

	publicKeys := make([]models.ShamirPublicKey, 0, n)
	privateKeyRings := make([]*crypto.KeyRing, 0, n)
	for i := 1; i <= n; i++ {
		privateKey, err := crypto.GenerateKey(
			fmt.Sprintf("test-key-%d", i),
			fmt.Sprintf("test-key-%d@example.com", i),
			"x25519",
			0,
		)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = privateKey.ClearPrivateParams()
		})

		privateKeyRing, err := crypto.NewKeyRing(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		privateKeyRings = append(privateKeyRings, privateKeyRing)

		armoredPublicKey, err := privateKey.GetArmoredPublicKey()
		if err != nil {
			t.Fatal(err)
		}
		publicKey, err := crypto.NewKeyFromArmored(armoredPublicKey)
		if err != nil {
			t.Fatal(err)
		}
		publicKeyRing, err := crypto.NewKeyRing(publicKey)
		if err != nil {
			t.Fatal(err)
		}

		publicKeys = append(publicKeys, models.ShamirPublicKey{
			ID:               i,
			IdentityName:     publicKey.GetEntity().PrimaryIdentity().Name,
			ArmoredPublicKey: armoredPublicKey,
			PublicKey:        publicKeyRing,
		})
	}

	return publicKeys, privateKeyRings
}

func decryptTestShare(privateKeyRing *crypto.KeyRing, armoredPGPMessage string) (shamir.Share, error) {
	pgpMessage, err := crypto.NewPGPMessageFromArmored(armoredPGPMessage)
	if err != nil {
		return shamir.Share{}, err
	}

	plainMessage, err := privateKeyRing.Decrypt(pgpMessage, nil, 0)
	if err != nil {
		return shamir.Share{}, err
	}

	return shamir.FromString(plainMessage.GetString())
}
