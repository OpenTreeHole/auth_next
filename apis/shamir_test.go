package apis

import (
	"math/big"
	"testing"

	"auth_next/utils/shamir"
)

func TestDecryptUserEmailWithFourSharesSkipsBadShare(t *testing.T) {
	const email = "test@example.com"

	shares, err := shamir.Encrypt(email, 5, 4)
	if err != nil {
		t.Fatal(err)
	}

	shares[2] = shamir.Share{
		X: big.NewInt(12345),
		Y: big.NewInt(67890),
	}

	response, ok := decryptUserEmailWithFourShares(1, shares, []string{"a", "b", "c", "d", "e"})
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
