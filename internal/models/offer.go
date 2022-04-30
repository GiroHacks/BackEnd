package models

import "time"

type Offer struct {
	ID              uint64    `json:"id,omitempty"`
	SiteID          uint64    `json:"site_id,omitempty"`
	PublicationDate time.Time `json:"publication_date"`
	Province        string    `json:"province,omitempty"`
	OfferType       string    `json:"offer_type,omitempty"`
	Industry        string    `json:"industry,omitempty"`
	JobTitle        string    `json:"job_title,omitempty"`
	Name            string    `json:"name,omitempty"`
	Description     string    `json:"description,omitempty"`
	Requirements    string    `json:"requirements,omitempty"`
	MinSalary       float64   `json:"min_salary,omitempty"`
	MaxSalary       float64   `json:"max_salary,omitempty"`
	NumViews        uint64    `json:"num_views,omitempty"`
	NumLeads        uint64    `json:"num_leads,omitempty"`
}

type UsersSkills struct {
	SkillID uint64 `json:"id"`
	Name    string `json:"name"`
}
