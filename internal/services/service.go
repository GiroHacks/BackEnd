package services

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/girohack/backend/internal/database"
	"github.com/girohack/backend/internal/models"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	db *database.PostgresDb
}

func New() (*Service, error) {
	dsn := "host=localhost user=root password=root dbname=postgres port=5432 sslmode=disable"
	db, err := database.NewPostgres(context.TODO(), dsn)
	if err != nil {
		return nil, err
	}

	return &Service{db: db}, nil
}

func (s *Service) Register() error {
	r := gin.Default()

	// // no tocar
	corsConfig := cors.DefaultConfig()
	corsConfig.AllowOrigins = []string{"*"}
	corsConfig.AllowWildcard = true
	corsConfig.AllowHeaders = []string{"Authorization", "Origin", "Content-Length", "Content-Type", "Access-Control-Allow-Headers", "Access-Control-Allow-Origin"}
	r.Use(cors.New(corsConfig))

	r.POST("/api/login", s.login())
	r.POST("/api/checkemail", s.checkEmail())
	r.POST("/api/register", s.register())
	r.GET("/api/users/me/skills", s.getMySkills())
	r.POST("/api/users/me/skills", s.setMySkills())
	r.GET("/api/users/me", s.getMyself())
	r.POST("/api/skills/find", s.findSkill())
	r.GET("/api/offers", s.getOffers())
	r.GET("/api/offers/:id", s.getOffer())

	return r.Run()
}

func erro(err error) gin.H {
	return gin.H{"error": err.Error()}
}

type Claims struct {
	ID        uint64 `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	jwt.StandardClaims
}

var privateSignature = []byte("imnotgaybut20dolarsare20dolars")
var errUnauthorized = errors.New("unauthorized")

func (s *Service) register() gin.HandlerFunc {
	type requestParams struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Phone     string `json:"phone"`
		// Birthdate time.Time `json:"birthdate"`
	}

	return func(c *gin.Context) {
		var req requestParams
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		b, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		// TODO(@sergivb01): fer parsing correcte datetime format
		user := models.User{
			Email:     req.Email,
			Password:  b,
			FirstName: req.FirstName,
			LastName:  req.LastName,
			Phone:     req.Phone,
			Birthdate: time.Now(),
		}

		if err := s.db.RegisterUser(context.TODO(), user); err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		c.JSON(http.StatusOK, "ok")
	}
}

func (s *Service) login() gin.HandlerFunc {
	type loginReq struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	return func(c *gin.Context) {
		var req loginReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		user, err := s.db.GetUser(context.TODO(), req.Email)
		if err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		if err := bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)); err != nil {
			if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
				return
			}
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			ID:        user.ID,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(privateSignature)
		if err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		res := struct {
			Token string `json:"token"`
		}{
			Token: tokenString,
		}

		c.JSON(http.StatusOK, res)
	}
}

func (s *Service) getUserFromReq(c *gin.Context) (models.User, error) {
	var user models.User
	h := c.GetHeader("Authorization")
	if h == "" {
		return user, errUnauthorized
	}

	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(h, claims, func(token *jwt.Token) (interface{}, error) {
		return privateSignature, nil
	})
	if err != nil {
		return models.User{}, err
	}
	if !tkn.Valid {
		return models.User{}, errors.New("invalid token")
	}

	user, err = s.db.GetUserById(context.TODO(), claims.ID)
	if err != nil {
		return models.User{}, err
	}

	return user, nil
}

func (s *Service) getMyself() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := s.getUserFromReq(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		c.JSON(http.StatusOK, user)
	}
}

func (s *Service) getMySkills() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := s.getUserFromReq(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		skills, err := s.db.GetSkills(context.TODO(), user.ID)
		if len(skills) == 0 {
			c.JSON(http.StatusOK, make([]string, 0))
			return
		}

		c.JSON(http.StatusOK, skills)
	}
}

func (s *Service) findSkill() gin.HandlerFunc {
	type requestParams struct {
		Name string `json:"name"`
	}
	return func(c *gin.Context) {
		var req requestParams
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		skills, err := s.db.SearchSkills(context.TODO(), req.Name)
		if err != nil {
			c.JSON(http.StatusInternalServerError, erro(err))
			return
		}

		if len(skills) == 0 {
			c.JSON(http.StatusOK, make([]string, 0))
			return
		}

		c.JSON(http.StatusOK, skills)
	}
}

func (s *Service) setMySkills() gin.HandlerFunc {
	type requestParams []uint64

	return func(c *gin.Context) {
		user, err := s.getUserFromReq(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		var req requestParams
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		if err := s.db.SetSkills(context.TODO(), user.ID, req); err != nil {
			c.JSON(http.StatusInternalServerError, erro(err))
			return
		}

		c.JSON(http.StatusOK, "ok")
	}
}

func (s *Service) checkEmail() gin.HandlerFunc {
	type requestParams struct {
		Email string `json:"email"`
	}
	return func(c *gin.Context) {
		var req requestParams
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		ok, err := s.db.ExistsEmail(context.TODO(), req.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, erro(err))
			return
		}

		if ok {
			c.JSON(http.StatusBadRequest, "exists")
			return
		}

		c.JSON(http.StatusOK, "does not exisdt")
	}
}

func (s *Service) getOffers() gin.HandlerFunc {
	return func(c *gin.Context) {
		jobs, err := s.db.GetJobs(context.TODO())
		if err != nil {
			c.JSON(http.StatusInternalServerError, erro(err))
			return
		}

		if len(jobs) == 0 {
			c.JSON(http.StatusOK, make([]string, 0))
			return
		}

		c.JSON(http.StatusOK, jobs)
	}
}

func (s *Service) getOffer() gin.HandlerFunc {
	return func(c *gin.Context) {
		rawID := c.Param("id")
		n, err := strconv.ParseUint(rawID, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		job, err := s.db.GetJob(context.TODO(), n)
		if err != nil {
			c.JSON(http.StatusBadRequest, erro(err))
			return
		}

		c.JSON(http.StatusOK, job)
	}
}
