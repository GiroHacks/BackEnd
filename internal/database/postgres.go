package database

import (
	"context"
	"fmt"

	"github.com/georgysavva/scany/pgxscan"
	"github.com/girohack/backend/internal/models"
	"github.com/jackc/pgx/v4/pgxpool"
)

type PostgresDb struct {
	db *pgxpool.Pool
}

func NewPostgres(ctx context.Context, uri string) (*PostgresDb, error) {
	pgxconfig, err := pgxpool.ParseConfig(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing db uri: %w", err)
	}

	db, err := pgxpool.ConnectConfig(ctx, pgxconfig)
	if err != nil {
		return nil, fmt.Errorf("connecting postgres: %w", err)
	}

	if err := db.Ping(ctx); err != nil {
		return nil, fmt.Errorf("pining postgres: %w", err)
	}

	return &PostgresDb{db: db}, nil
}

func (p *PostgresDb) RegisterUser(ctx context.Context, user models.User) error {
	_, err := p.db.Exec(ctx, "INSERT INTO users (email, password, firstname, lastname, phone, birthdate) VALUES ($1, $2, $3, $4, $5, $6)",
		user.Email, user.Password, user.FirstName, user.LastName, user.Phone, user.Birthdate)
	return err
}

func (p *PostgresDb) GetUserById(ctx context.Context, id uint64) (models.User, error) {
	rows, err := p.db.Query(ctx, "SELECT id, email, password, firstname, lastname, phone, birthdate FROM users WHERE id = $1", id)
	if err != nil {
		return models.User{}, err
	}
	defer rows.Close()

	var user models.User
	if err := pgxscan.ScanOne(&user, rows); err != nil {
		return models.User{}, err
	}

	return user, nil
}

func (p *PostgresDb) GetUser(ctx context.Context, email string) (models.User, error) {
	rows, err := p.db.Query(ctx, "SELECT id, email, password, firstname, lastname, phone, birthdate FROM users WHERE email = $1", email)
	if err != nil {
		return models.User{}, err
	}
	defer rows.Close()

	var user models.User
	if err := pgxscan.ScanOne(&user, rows); err != nil {
		return models.User{}, err
	}

	return user, nil
}
