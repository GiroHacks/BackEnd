package services

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/girohack/backend/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Service struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Register() error {
	r := gin.Default()
	r.GET("/ping", s.ping())

	return r.Run()
}

func (s *Service) ping() func(c *gin.Context) {

	return func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	}
}

func (s *Service) login() func(c *gin.Context) {
	type loginReq struct {
		Username string
		Password string
	}

	type loginRes struct {
	}

	return func(c *gin.Context) {
		var req loginReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var user models.User
		if err := s.db.Where("username = ?", req.Username).First(&user).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"ok": "penis"})
	}
}
