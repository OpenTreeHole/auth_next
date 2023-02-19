package shamir

import (
	"auth_next/utils"
	"crypto/rand"
	"errors"
	"fmt"
	. "math/big"
)

var P *Int

const MaxLength = 64

func init() {
	P = new(Int).Sub(new(Int).Exp(NewInt(2), NewInt(521), nil), NewInt(1)) // P = 2 ** 521 - 1
}

type Share struct {
	X *Int `json:"x"`
	Y *Int `json:"y"`
}

type Shares []Share

func (share Share) ToString() string {
	return fmt.Sprintf("%d\n%d", share.X, share.Y)
}

func FromString(rawShare string) (Share, error) {
	share := Share{new(Int), new(Int)}
	_, err := fmt.Sscanf(rawShare, "%v\n%v", share.X, share.Y)
	if err != nil {
		return share, err
	}
	return share, nil
}

func (share *Share) UnmarshalText(b []byte) (err error) {
	*share, err = FromString(string(b))
	return err
}

func (share Share) MarshalText() ([]byte, error) {
	return []byte(share.ToString()), nil
}

// extendedGCD 扩展欧几里得算法，求不定方程ax + by = 1的可行x, y值，非递归线性解法
// https://zhuanlan.zhihu.com/p/58241990
func extendedGCD(a *Int, b *Int) (*Int, *Int) {
	// initialize Identity Matrix
	m, n := NewInt(0), NewInt(1)
	x, y := NewInt(1), NewInt(0)
	for b.BitLen() != 0 {
		quot, mod := new(Int).DivMod(a, b, new(Int))
		a, b = b, mod
		x, m = m, new(Int).Sub(x, new(Int).Mul(quot, m)) // x, m = m, x - quot * m
		y, n = n, new(Int).Sub(y, new(Int).Mul(quot, n)) // y, n = n, y - quot * n
	}
	return x, y
}

// ModularMultiplicativeInverse 求x mod p的逆元
func ModularMultiplicativeInverse(x *Int) *Int {
	ans, _ := extendedGCD(new(Int).Set(x), new(Int).Set(P))
	return ans
}

// Lagrange 计算拉格朗日差值多项式的常数项 a0
func Lagrange(shares []Share) *Int {
	s := NewInt(0)
	xArray := make([]*Int, len(shares))
	for i := range xArray {
		xArray[i] = shares[i].X
	}
	for i := range xArray {
		pi := NewInt(1)
		for j := range shares {
			if i == j {
				continue
			}
			// pi = (pi * x[j] * (x[j] - x[i])^{-1}) % P
			pi = new(Int).Mod(new(Int).Mul(pi, new(Int).Mul(xArray[j], ModularMultiplicativeInverse(new(Int).Sub(xArray[j], xArray[i])))), P)
		}
		// s = (s + y[i] * pi) % P
		s = new(Int).Mod(new(Int).Add(s, new(Int).Mul(shares[i].Y, pi)), P)
	}
	return s
}

func Generate(secret *Int, num, threshold int) ([]Share, error) {
	evaluate := func(coefficients []*Int, x *Int) *Int {
		ans := NewInt(0)
		power := NewInt(1)
		for _, c := range coefficients {
			// ans = (ans + c * power) % P
			ans = new(Int).Mod(new(Int).Add(ans, new(Int).Mul(c, power)), P)
			// power = (power * x) % P
			power = new(Int).Mod(new(Int).Mul(power, x), P)
		}
		return ans
	}

	coefficient := make([]*Int, threshold)
	coefficient[0] = new(Int).Set(secret)
	for i := 1; i < threshold; i++ {
		c, err := rand.Int(rand.Reader, P)
		if err != nil {
			return nil, err
		}
		coefficient[i] = c
	}

	shares := make([]Share, num)
	for i := range shares {
		x, err := rand.Int(rand.Reader, P)
		if err != nil {
			return nil, err
		}
		shares[i] = Share{x, evaluate(coefficient, x)}
	}
	return shares, nil
}

func Encrypt(secret string, num, threshold int) ([]Share, error) {
	if len(secret) > MaxLength {
		return nil, errors.New(fmt.Sprintf("length of secret should less than %d", MaxLength))
	}
	s := new(Int).SetBytes(utils.SliceReverse([]byte(secret)))
	if s.Cmp(P) >= 0 {
		return nil, errors.New(fmt.Sprintf("secret should not bigger than P = %d", P))
	}
	if threshold == 0 {
		threshold = num/2 + 1
	} else if threshold > num {
		return nil, errors.New("threshold is bigger than num, secret could not be recovered")
	}
	return Generate(s, num, threshold)
}

func Decrypt(shares []Share) string {
	return string(utils.SliceReverse(Lagrange(shares).Bytes()))
}
