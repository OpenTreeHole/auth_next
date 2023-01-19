package shamir

import (
	"fmt"
	. "math/big"
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
