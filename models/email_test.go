package models

import "testing"

func TestSha3SumEmail(t *testing.T) {
	email := "21307130001@m.fudan.edu.cn"
	println(Sha3SumEmail(email))
}
