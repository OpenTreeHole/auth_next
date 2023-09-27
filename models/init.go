package models

import (
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"auth_next/config"
)

func InitDB() {
	// connect to database and auto migrate models
	initDB()

	// get admin list for admin check and start admin refresh task
	InitAdminList()

	// get shamir admin list and start refresh task
	InitShamirAdminList()

	// get pgp public key for register
	InitShamirPublicKey()
}

var DB *gorm.DB

var gormConfig = &gorm.Config{
	NamingStrategy: schema.NamingStrategy{
		SingularTable: true, // use singular table name, table for `User` would be `user` with this option enabled
	},
	Logger: logger.New(
		&log.Logger,
		logger.Config{
			SlowThreshold:             time.Second,  // 慢 SQL 阈值
			LogLevel:                  logger.Error, // 日志级别
			IgnoreRecordNotFoundError: true,         // 忽略ErrRecordNotFound（记录未找到）错误
			Colorful:                  false,        // 禁用彩色打印
		},
	),
}

func initDB() {
	mysqlDB := func() (*gorm.DB, error) {
		return gorm.Open(mysql.Open(config.Config.DbUrl), gormConfig)
	}
	sqliteDB := func() (*gorm.DB, error) {
		err := os.MkdirAll("data", 0755)
		if err != nil && !os.IsExist(err) {
			log.Fatal().Err(err).Msg("create data directory failed")
		}
		return gorm.Open(sqlite.Open("data/sqlite.db"), gormConfig)
	}
	memoryDB := func() (*gorm.DB, error) {
		return gorm.Open(sqlite.Open("file::memory:?cache=shared"), gormConfig)
	}

	var err error

	// connect to database with different mode
	switch config.Config.Mode {
	case "production":
		DB, err = mysqlDB()
	case "dev":
		if config.Config.DbUrl == "" {
			DB, err = sqliteDB()
		} else {
			DB, err = mysqlDB()
		}
	case "test":
		DB, err = memoryDB()
	case "bench":
		if config.Config.DbUrl == "" {
			DB, err = memoryDB()
		} else {
			DB, err = mysqlDB()
		}
	default:
		log.Fatal().Str("scope", "init db").Msg("unknown mode")
	}

	if err != nil {
		log.Fatal().Err(err).Msg("connect to database failed")
	}

	if config.Config.Mode == "dev" || config.Config.Mode == "test" {
		DB = DB.Debug()
	}

	sqlDB, err := DB.DB()
	if err != nil {
		log.Fatal().Err(err).Msg("get sql.DB failed")
	}

	sqlDB.SetConnMaxLifetime(time.Hour)

	// migrate database
	err = DB.AutoMigrate(
		User{},
		ShamirEmail{},
		ActiveStatus{},
		DeleteIdentifier{},
	)
	if err != nil {
		log.Fatal().Err(err).Msg("auto migrate failed")
	}
	if config.Config.ShamirFeature {
		err = DB.AutoMigrate(ShamirPublicKey{})
		if err != nil {
			log.Fatal().Err(err).Msg("auto migrate failed")
		}
	}
	if config.Config.Standalone {
		err = DB.AutoMigrate(UserJwtSecret{})
		if err != nil {
			log.Fatal().Err(err).Msg("auto migrate failed")
		}
	}
}
