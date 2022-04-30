package models

import "time"

type User struct {
	ID        uint64
	Email     string    `json:"email"`
	Password  []byte    `json:"-"`
	FirstName string    `json:"first_name" db:"firstname"`
	LastName  string    `json:"last_name" db:"lastname"`
	Phone     string    `json:"phone"`
	Birthdate time.Time `json:"birthdate"`
}

type Skill struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
}
