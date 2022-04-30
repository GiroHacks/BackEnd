package models

import (
	"time"
)

type Offer struct {
	IdOriginal      uint64
	Province        string
	OfferType       string
	Industry        string
	JobTitle        string
	Name            string
	Description     string
	Requirements    string
	SalaryMin       uint64
	SalaryMax       uint64
	NumViews        uint64
	NumLeads        uint64
	PublicationDate time.Time
}
