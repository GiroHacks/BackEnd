package main

import (
	"github.com/girohack/backend/internal/services"
)

func main() {
	svc, err := services.New()
	if err != nil {
		panic(err)
	}
	if err := svc.Register(); err != nil {
		panic(err)
	}
}
