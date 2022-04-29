package main

import (
	"log"

	"github.com/girohack/backend/internal/models"
	"github.com/girohack/backend/internal/services"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	dsn := "host=localhost user=gorm password=gorm dbname=gorm port=9920 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	if err := db.AutoMigrate(&models.User{}); err != nil {
		log.Fatal(err.Error())
	}

	svc := services.New(db)
	if err := svc.Register(); err != nil {
		panic(err)
	}
}
