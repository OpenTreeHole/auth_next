package apis

import (
	"bytes"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/opentreehole/go-common"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"auth_next/config"
	"auth_next/models"
	"auth_next/utils/auth"
)

func TestChangePasswordRejectsInactiveUser(t *testing.T) {
	oldDB := models.DB
	oldStandalone := config.Config.Standalone
	oldShamirFeature := config.Config.ShamirFeature
	oldEmailWhitelist := config.Config.EmailWhitelist
	oldVerificationCodeExpires := config.Config.VerificationCodeExpires
	t.Cleanup(func() {
		models.DB = oldDB
		config.Config.Standalone = oldStandalone
		config.Config.ShamirFeature = oldShamirFeature
		config.Config.EmailWhitelist = oldEmailWhitelist
		config.Config.VerificationCodeExpires = oldVerificationCodeExpires
	})

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
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
	if err := db.AutoMigrate(models.User{}, models.DeleteIdentifier{}, models.UserJwtSecret{}); err != nil {
		t.Fatal(err)
	}

	models.DB = db
	config.Config.Standalone = true
	config.Config.ShamirFeature = false
	config.Config.EmailWhitelist = nil
	config.Config.VerificationCodeExpires = 5
	auth.InitVerificationCodeCache()

	const email = "inactive@example.com"
	oldPassword, err := auth.MakePassword("old-password")
	if err != nil {
		t.Fatal(err)
	}
	user := models.User{
		Identifier: sql.NullString{String: auth.MakeIdentifier(email), Valid: true},
		Password:   oldPassword,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&user).Update("is_active", false).Error; err != nil {
		t.Fatal(err)
	}

	code, err := auth.SetVerificationCode(email, "reset")
	if err != nil {
		t.Fatal(err)
	}

	app := fiber.New(fiber.Config{ErrorHandler: common.ErrorHandler})
	app.Put("/register", ChangePassword)

	body := fmt.Sprintf(
		`{"email":%q,"password":"new-password","verification":%q}`,
		email,
		code,
	)
	req := httptest.NewRequest(http.MethodPut, "/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, resp.StatusCode)
	}

	var updated models.User
	if err := db.Take(&updated, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if updated.IsActive {
		t.Fatal("expected inactive user to remain inactive after password reset attempt")
	}
	ok, err := auth.CheckPassword("new-password", updated.Password)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected inactive user's password not to be changed")
	}
}
