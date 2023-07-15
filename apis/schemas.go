package apis

import (
	"auth_next/models"
	"auth_next/utils/shamir"
	"fmt"
	"strconv"
	"strings"
)

/* account */

type EmailModel struct {
	// email in email blacklist
	Email string `json:"email" query:"email" validate:"isValidEmail"`
}

type LoginRequest struct {
	EmailModel
	Password string `json:"password" minLength:"8"`
}

type TokenResponse struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
	Message string `json:"message"`
}

type RegisterRequest struct {
	LoginRequest
	Verification VerificationType `json:"verification" minLength:"6" maxLength:"6" swaggerType:"string"`
}

type RegisterInBatchRequest struct {
	Data []LoginRequest `json:"data"`
}

type VerificationType string

func (v *VerificationType) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	// Ignore null, like in the main JSON package.
	if s == "null" {
		return nil
	}

	number, err := strconv.Atoi(s)
	if err != nil {
		return err
	}

	*v = VerificationType(fmt.Sprintf("%06d", number))
	return nil
}

func (v *VerificationType) UnmarshalText(data []byte) error {
	s := strings.Trim(string(data), `"`)
	// Ignore null, like in the main JSON package.
	if s == "" {
		return nil
	}

	*v = VerificationType(s)
	return nil
}

type EmailVerifyResponse struct {
	Message string `json:"message"`
	Scope   string `json:"scope" enums:"register,reset"`
}

type ApikeyRequest struct {
	EmailModel
	Apikey        string `json:"apikey" query:"apikey"`
	CheckRegister bool   `json:"check_register" query:"check_register" default:"false"` // if true, return whether registered
}

type ApikeyResponse struct {
	EmailVerifyResponse
	Code string `json:"code"`
}

/* user account */

type ModifyUserRequest struct {
	Nickname *string `json:"nickname" validate:"omitempty,min=1"`
}

/* shamir */

type PGPMessageRequest struct {
	IdentityName string `json:"identity_name" query:"identity_name" validate:"required"`
}

type PGPMessageResponse struct {
	UserID     int    `json:"user_id"`
	PGPMessage string `json:"pgp_message" gorm:"column:key"`
}

type UserShare struct {
	UserID int          `json:"user_id"`
	Share  shamir.Share `json:"share" swaggerType:"string"`
}

type UploadSharesRequest struct {
	PGPMessageRequest
	Shares []UserShare `json:"shares" query:"shares"`
}

type UploadPublicKeyRequest struct {
	Data []string `json:"data" validate:"required,len=7"` // all standalone public keys
}

type IdentityNameResponse struct {
	IdentityNames []string `json:"identity_names"`
}

type ShamirStatusResponse struct {
	ShamirUpdateReady           bool                     `json:"shamir_update_ready"`
	ShamirUpdating              bool                     `json:"shamir_updating"`
	UploadedSharesIdentityNames []string                 `json:"uploaded_shares_identity_names"`
	UploadedShares              map[int]shamir.Shares    `json:"-"`
	CurrentPublicKeys           []models.ShamirPublicKey `json:"current_public_keys"`
	NewPublicKeys               []models.ShamirPublicKey `json:"new_public_keys"`
	NowUserID                   int                      `json:"now_user_id,omitempty"`
	FailMessage                 string                   `json:"fail_message,omitempty"`
	WarningMessage              string                   `json:"warning_message,omitempty"`
}
