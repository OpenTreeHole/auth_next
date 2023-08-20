package models

import (
	"time"

	"github.com/rs/zerolog/log"
)

type ActiveStatus struct {
	ID        int
	CreatedAt time.Time
	DAU       int
	MAU       int
}

func ActiveStatusTask() {
	var dau, mau int64
	err := DB.Model(&User{}).
		Where("last_login between ? and ?", time.Now().Add(-24*time.Hour), time.Now()).
		Count(&dau).Error
	if err != nil {
		log.Err(err).Msg("load dau err")
		return
	}
	err = DB.Model(&User{}).
		Where("last_login between ? and ?", time.Now().AddDate(0, -1, 0), time.Now()).
		Count(&mau).Error
	if err != nil {
		log.Err(err).Msg("load mau err")
		return
	}

	status := ActiveStatus{
		DAU: int(dau),
		MAU: int(mau),
	}
	err = DB.Create(&status).Error
	if err != nil {
		log.Err(err).Msg("save status err")
	}
}
