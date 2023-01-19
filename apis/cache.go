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
		ShamirUpdateReady:           false,
		UploadedSharesIdentityNames: make([]string, 0, 7),
		UploadedShares:              make(map[int]shamir.Shares, 0),
		NewPublicKeys:               make([]models.ShamirPublicKey, 0, 7),
		ShamirUpdating:              false,
		NowUserID:                   0,
	}
}
