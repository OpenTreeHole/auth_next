package auth

import (
	"auth_next/config"
	"github.com/go-playground/assert/v2"
	"testing"
)

func TestCheckPassword(t *testing.T) {
	rawPassword := "1234567890"
	encryptPassword := "pbkdf2_sha256$216000$dYxeEYraGSmj$QEOeBVq9oLuVS6T/vlpkzR7fMmAydKfP2SKo5XsiGOI="

	ok, err := CheckPassword(rawPassword, encryptPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("error check password")
	}
}

func TestMakePassword(t *testing.T) {
	rawPassword := "1234567890"
	encryptPassword, err := MakePassword(rawPassword)
	if err != nil {
		t.Fatal(err)
	}
	println(encryptPassword)

	ok, err := CheckPassword(rawPassword, encryptPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("error check password")
	}
}

func TestMakeIdentifier(t *testing.T) {
	rawEmail := "test@fduhole.com"
	var encryptEmail string
	if config.FileConfig.IdentifierSalt != "" {
		// for production test
		encryptEmail = "5b39477c0b6403e22a2f9494ebcd9ba826101e936bb98c7e8a8a0f295c2eb0034c02bb3c0b1fc7a9ef4c5b01e0dfac71387b5150ae30883c2cbf4fadc25c6f54"
	} else {
		// for local unit test
		encryptEmail = "98cb944410fc8154f7936374d9bebacaa9049223cb3bb5d8bd259969c0649a7720f86a25927c1fbae6bebf2d7542a89ff066a50dd5395dd71a90f90255862be2"
	}

	assert.Equal(t, encryptEmail, MakeIdentifier(rawEmail))
}
