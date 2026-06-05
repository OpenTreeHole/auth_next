package shamir

import (
	"fmt"
	. "math/big"
	"strings"
	"testing"
)

func TestShare_ToString(t *testing.T) {
	fmt.Println(Share{X: new(Int).SetInt64(1 << 10), Y: new(Int).SetInt64(1 << 60)}.ToString())
}

func TestFromString(t *testing.T) {
	share, err := FromString("12333333333333333333333333\n45666666666666666666666666666")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(share)
}

func TestFromStringAllowsSurroundingWhitespace(t *testing.T) {
	share, err := FromString(" \r\n12333333333333333333333333\r\n45666666666666666666666666666\n ")
	if err != nil {
		t.Fatal(err)
	}
	if share.X.String() != "12333333333333333333333333" {
		t.Fatalf("unexpected x coordinate: %s", share.X)
	}
	if share.Y.String() != "45666666666666666666666666666" {
		t.Fatalf("unexpected y coordinate: %s", share.Y)
	}
}

func TestFromStringRejectsEmptyShare(t *testing.T) {
	_, err := FromString("")
	if err == nil {
		t.Fatal("expected empty share to fail")
	}
	if strings.Contains(err.Error(), "number has no digits") {
		t.Fatalf("expected a clear share format error, got %q", err)
	}
}

func TestFromStringRejectsInvalidCoordinate(t *testing.T) {
	_, err := FromString("123\n")
	if err == nil {
		t.Fatal("expected incomplete share to fail")
	}
	if !strings.Contains(err.Error(), "expected exactly two decimal integer coordinates") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = FromString("123\nabc")
	if err == nil {
		t.Fatal("expected invalid y coordinate to fail")
	}
	if !strings.Contains(err.Error(), "invalid share y coordinate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	secret := "123456"
	shares, err := Encrypt(secret, 7, 4)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(secret)
	fmt.Println(shares)
	fmt.Println(Decrypt(shares))
}

func TestModularMultiplicativeInverse(t *testing.T) {
	fmt.Println(ModularMultiplicativeInverse(NewInt(100)))
}
