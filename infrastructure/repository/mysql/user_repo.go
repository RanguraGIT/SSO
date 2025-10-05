package mysql

import (
	"context"
	"database/sql"

	"github.com/RanguraGIT/sso/domain/entity"
	"github.com/RanguraGIT/sso/domain/repository"
	"github.com/google/uuid"
)

type UserRepo struct{ db *sql.DB }

func NewUserRepo(db *sql.DB) repository.UserRepository { return &UserRepo{db: db} }

func (r *UserRepo) GetByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id,email,password_hash,email_verified,locked,created_at,updated_at FROM users WHERE id=?`, id.String())
	u := &entity.User{}
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.Locked, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id,email,password_hash,email_verified,locked,created_at,updated_at FROM users WHERE email=?`, email)
	u := &entity.User{}
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.EmailVerified, &u.Locked, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) Create(ctx context.Context, u *entity.User) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO users(id,email,password_hash,email_verified,locked,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`, u.ID.String(), u.Email, u.PasswordHash, u.EmailVerified, u.Locked, u.CreatedAt, u.UpdatedAt)
	return err
}

func (r *UserRepo) Update(ctx context.Context, u *entity.User) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET email=?, password_hash=?, email_verified=?, locked=?, updated_at=NOW(6) WHERE id=?`, u.Email, u.PasswordHash, u.EmailVerified, u.Locked, u.ID.String())
	return err
}
