package apis

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/opentreehole/go-common"

	"auth_next/config"
)

type VerificationModel struct {
	Verification VerificationType `json:"verification"`
}

func TestVerificationModel(t *testing.T) {
	for _, data := range []any{
		`"123456"`,
		`"012345"`,
		123456,
		12345,
	} {
		jsonString := fmt.Sprintf(`{"verification": %v}`, data)
		var model VerificationModel
		err := json.Unmarshal([]byte(jsonString), &model)
		if err != nil {
			t.Error(err)
		}
		fmt.Println(model.Verification)
	}
}

func TestRegisterRequestRejectsWhitespaceEmail(t *testing.T) {
	config.Config.EmailWhitelist = []string{"fudan.edu.cn", "m.fudan.edu.cn"}

	for _, email := range []string{
		" student001@m.fudan.edu.cn",
		"student002 @m.fudan.edu.cn",
		"\tstudent003@fudan.edu.cn",
	} {
		body := RegisterRequest{
			LoginRequest: LoginRequest{
				EmailModel: EmailModel{Email: email},
				Password:   "password123",
			},
			Verification: "000000",
		}
		if err := common.ValidateStruct(body); err == nil {
			t.Fatalf("expected validation error for email %q", email)
		}
	}
}
