package apis

import (
	"auth_next/models"
	"auth_next/utils/shamir"
	"sync"
)

var GlobalUploadShamirStatus struct {
	sync.Mutex
	ShamirStatusResponse
}

func init() {
	GlobalUploadShamirStatus.ShamirStatusResponse = ShamirStatusResponse{
		UploadedShares:    make(map[int]shamir.Shares, 0),
		CurrentPublicKeys: models.ShamirPublicKeys,
	}
}
