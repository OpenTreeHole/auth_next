package apis

import (
	"encoding/json"
	"fmt"
	"testing"
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
