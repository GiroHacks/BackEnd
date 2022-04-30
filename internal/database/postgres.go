package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/georgysavva/scany/pgxscan"
	"github.com/girohack/backend/internal/models"
	"github.com/jackc/pgx/v4"
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

func (p *PostgresDb) GetSkills(ctx context.Context, id uint64) ([]models.UsersSkills, error) {
	rows, err := p.db.Query(ctx, `SELECT s.id AS skill_id, s.name AS name FROM users_skills
       	JOIN skills s on users_skills.skill_id = s.id
       	WHERE user_id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var data []models.UsersSkills
	if err := pgxscan.ScanAll(&data, rows); err != nil {
		return nil, err
	}

	return data, nil
}

func (p *PostgresDb) SetSkills(ctx context.Context, userId uint64, ids []uint64) error {
	tx, err := p.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "DELETE FROM users_skills WHERE user_id = $1", userId); err != nil {
		return err
	}

	for _, id := range ids {
		if _, err := tx.Exec(ctx, "INSERT INTO users_skills (user_id, skill_id) VALUES ($1, $2)", userId, id); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (p *PostgresDb) SearchSkills(ctx context.Context, val string) ([]models.Skill, error) {
	rows, err := p.db.Query(ctx, "SELECT id, name FROM skills WHERE name LIKE $1 LIMIT 10", "%"+strings.ToUpper(val)+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []models.Skill
	if err := pgxscan.ScanAll(&res, rows); err != nil {
		return nil, err
	}

	return res, nil
}

func (p *PostgresDb) ExistsEmail(ctx context.Context, email string) (bool, error) {
	rows, err := p.db.Query(ctx, "SELECT count(*) FROM users WHERE email = $1", email)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	var a int
	if err := pgxscan.ScanOne(&a, rows); err != nil {
		return false, err
	}

	return a != 0, nil
}

func (p *PostgresDb) GetJobs(ctx context.Context) ([]models.Offer, error) {
	rows, err := p.db.Query(ctx, "SELECT id, site_id, publication_date, province, offer_type, industry, job_title, name, description, requirements, min_salary, max_salary, num_views, num_leads FROM offers LIMIT 10")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.Offer
	if err := pgxscan.ScanAll(&users, rows); err != nil {
		return nil, err
	}

	return users, nil
}

func (p *PostgresDb) GetJob(ctx context.Context, id uint64) (models.Offer, error) {
	rows, err := p.db.Query(ctx, "SELECT id, site_id, publication_date, province, offer_type, industry, job_title, name, description, requirements, min_salary, max_salary, num_views, num_leads FROM offers WHERE id = $1", id)
	if err != nil {
		return models.Offer{}, err
	}
	defer rows.Close()

	var offer models.Offer
	if err := pgxscan.ScanOne(&offer, rows); err != nil {
		return models.Offer{}, err
	}

	return offer, nil
}
