package models

import (
	"auth_next/config"
	"errors"
	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
	"os"
)

func init() {
	var err error

	// connect to database and auto migrate models
	err = initDB()
	if err != nil {
		panic(err)
	}

	// get admin list for admin check
	err = GetAdminList()
	if err != nil {
		panic(err)
	}

	// get pgp public key for register
	err = LoadShamirPublicKey()
	if err != nil {
		panic(err)
	}
}

var DB *gorm.DB

var gormConfig = &gorm.Config{
	NamingStrategy: schema.NamingStrategy{
		SingularTable: true, // use singular table name, table for `User` would be `user` with this option enabled
	},
}

func initDB() error {
	mysqlDB := func() (*gorm.DB, error) {
		return gorm.Open(mysql.Open(config.Config.DbUrl), gormConfig)
	}
	sqliteDB := func() (*gorm.DB, error) {
		err := os.MkdirAll("data", 0755)
		if err != nil && !os.IsExist(err) {
			panic(err)
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
		return errors.New("unsupported mode")
	}

	if err != nil {
		return err
	}

	if config.Config.Mode == "dev" || config.Config.Mode == "test" {
		DB = DB.Debug()
	}

	// migrate database
	err = DB.AutoMigrate(User{}, ShamirEmail{})
	if err != nil {
		return err
	}
	if config.Config.ShamirFeature {
		return DB.AutoMigrate(ShamirPublicKey{})
	} else {
		return nil
	}

}
